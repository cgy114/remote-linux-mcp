#Requires -Version 5.1
<#
.SYNOPSIS
remote-mcp 安装/卸载共享模块。

.DESCRIPTION
只提供函数定义，导入时没有文件、注册表或网络副作用。
所有外部命令都以「可执行文件 + 参数数组」调用，不经过字符串拼接；
本模块不读取也不打印任何密码或凭据内容。
#>

$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# ---------------------------------------------------------------------------
# 内部辅助函数（不导出）
# ---------------------------------------------------------------------------

function Add-LogLine {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Line
    )

    try {
        $directory = Split-Path -Parent $Path
        if ($directory -and -not (Test-Path -LiteralPath $directory)) {
            New-Item -ItemType Directory -Force -Path $directory | Out-Null
        }
        [System.IO.File]::AppendAllText(
            $Path,
            $Line + [Environment]::NewLine,
            $script:Utf8NoBom
        )
    }
    catch {
        Write-Host "[WARN] 无法写入日志文件: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [string]$WorkingDirectory
    )

    $pushed = $false
    $output = @()
    $exitCode = 1
    try {
        if ($WorkingDirectory) {
            Push-Location -LiteralPath $WorkingDirectory
            $pushed = $true
        }
        $output = & $FilePath @ArgumentList 2>&1
        $exitCode = $LASTEXITCODE
    }
    catch {
        $output = @($_.Exception.Message)
        $exitCode = 1
    }
    finally {
        if ($pushed) { Pop-Location }
    }

    $text = ($output | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.ToString() }
        else { [string]$_ }
    }) -join [Environment]::NewLine

    return [pscustomobject]@{
        ExitCode = $exitCode
        Output   = $text
    }
}

function ConvertFrom-QuotedArgLine {
    param([string]$Line)

    if ([string]::IsNullOrWhiteSpace($Line)) { return @() }

    $items = New-Object System.Collections.Generic.List[string]
    $regex = [regex]'"([^"]*)"|''([^'']*)''|(\S+)'
    foreach ($match in $regex.Matches($Line)) {
        if ($match.Groups[1].Success) { $items.Add($match.Groups[1].Value) }
        elseif ($match.Groups[2].Success) { $items.Add($match.Groups[2].Value) }
        else { $items.Add($match.Groups[3].Value) }
    }
    return $items.ToArray()
}

function Normalize-ComparisonText {
    param([string]$Text)

    if ($null -eq $Text) { return '' }
    $value = $Text.Trim()
    if ($value.Length -ge 2 -and $value.StartsWith('"') -and $value.EndsWith('"')) {
        $value = $value.Substring(1, $value.Length - 2)
    }
    $value = $value -replace '\s+', ' '
    $value = $value -replace '/', '\'
    return $value.Trim()
}

function Test-ArgListsMatch {
    param(
        [string[]]$Actual,
        [string[]]$Expected,
        [string]$ActualLine,
        [string[]]$ExpectedLineSource
    )

    if ($null -eq $Actual) { $Actual = @() }
    if ($null -eq $Expected) { $Expected = @() }

    if ($Actual.Count -eq $Expected.Count) {
        $same = $true
        for ($i = 0; $i -lt $Expected.Count; $i++) {
            $a = Normalize-ComparisonText $Actual[$i]
            $b = Normalize-ComparisonText $Expected[$i]
            if (-not [string]::Equals($a, $b, [System.StringComparison]::OrdinalIgnoreCase)) {
                $same = $false
                break
            }
        }
        if ($same) { return $true }
    }

    # claude mcp get 的 Args 行可能不保留引号；用整行文本兜底比较。
    $actualText = Normalize-ComparisonText $ActualLine
    $expectedText = Normalize-ComparisonText ($ExpectedLineSource -join ' ')
    return [string]::Equals($actualText, $expectedText, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# 公开函数
# ---------------------------------------------------------------------------

function Initialize-ConsoleEncoding {
    <#
    .SYNOPSIS
    把控制台输入/输出切到 UTF-8，避免 Windows PowerShell 5.1 下中文提示乱码。
    #>
    [CmdletBinding()]
    param()

    try {
        [Console]::OutputEncoding = $script:Utf8NoBom
        [Console]::InputEncoding = $script:Utf8NoBom
        $global:OutputEncoding = $script:Utf8NoBom
    }
    catch {
        # 某些宿主（例如无控制台的重定向环境）无法设置编码，忽略即可。
    }
}

function Get-RemoteMcpContext {
    <#
    .SYNOPSIS
    返回仓库、配置、安装状态与 CLI 的绝对路径。
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPathOverride
    )

    $scriptsRoot = Split-Path -Parent $PSScriptRoot
    $installRoot = Split-Path -Parent $scriptsRoot

    $homeDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    if ([string]::IsNullOrWhiteSpace($homeDir)) { $homeDir = $env:USERPROFILE }

    $configDir = Join-Path $homeDir '.remote-mcp'
    $defaultConfigPath = Join-Path $configDir 'config.yaml'

    $localAppData = $env:LOCALAPPDATA
    if ([string]::IsNullOrWhiteSpace($localAppData)) {
        $localAppData = Join-Path $homeDir 'AppData\Local'
    }
    $stateDir = Join-Path $localAppData 'remote-mcp'
    $statePath = Join-Path $stateDir 'install.json'

    $packageJsonPath = Join-Path $installRoot 'package.json'
    $version = '0.0.0'
    if (Test-Path -LiteralPath $packageJsonPath) {
        try {
            $package = Get-Content -LiteralPath $packageJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($package.version) { $version = [string]$package.version }
        }
        catch {
            # 版本读取失败不阻断安装，后续 --version 校验会暴露问题。
        }
    }

    $configPath = $defaultConfigPath
    if (-not [string]::IsNullOrWhiteSpace($ConfigPathOverride)) {
        $configPath = [System.IO.Path]::GetFullPath($ConfigPathOverride)
    }

    return [pscustomobject]@{
        InstallRoot        = $installRoot
        ScriptsRoot        = $scriptsRoot
        SrcRoot            = Join-Path $installRoot 'src'
        DistRoot           = Join-Path $installRoot 'dist'
        CliPath            = Join-Path $installRoot 'dist\cli.js'
        CheckConfigPath    = Join-Path $scriptsRoot 'check-config.mjs'
        PackageJsonPath    = $packageJsonPath
        TsConfigPath       = Join-Path $installRoot 'tsconfig.json'
        ConfigExamplePath  = Join-Path $installRoot 'config.example.yaml'
        HomeDir            = $homeDir
        ConfigDir          = $configDir
        ConfigPath         = $configPath
        DefaultConfigPath  = $defaultConfigPath
        StateDir           = $stateDir
        StatePath          = $statePath
        McpName            = 'remote-mcp'
        Scope              = 'user'
        Version            = $version
        IsWindows          = ($env:OS -eq 'Windows_NT')
    }
}

function Resolve-ExternalCommand {
    <#
    .SYNOPSIS
    解析外部可执行文件，返回绝对路径或 $null。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string[]]$PreferredExtensions = @(),
        [string[]]$CandidatePaths = @()
    )

    $allCandidates = New-Object System.Collections.Generic.List[string]

    if (Test-Path -LiteralPath $Name -PathType Leaf) {
        $allCandidates.Add([System.IO.Path]::GetFullPath($Name))
    }

    foreach ($candidate in $CandidatePaths) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $expanded = [Environment]::ExpandEnvironmentVariables($candidate)
        if (Test-Path -LiteralPath $expanded -PathType Leaf) {
            $allCandidates.Add([System.IO.Path]::GetFullPath($expanded))
        }
    }

    if ($allCandidates.Count -eq 0) {
        $commands = @(Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue)
        foreach ($command in $commands) {
            if ($command -and $command.Source) {
                $allCandidates.Add([System.IO.Path]::GetFullPath($command.Source))
            }
        }
    }

    if ($allCandidates.Count -eq 0) { return $null }

    foreach ($extension in $PreferredExtensions) {
        foreach ($candidate in $allCandidates) {
            if ($candidate.EndsWith($extension, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $candidate
            }
        }
    }

    return $allCandidates[0]
}

function Test-NodeRuntime {
    <#
    .SYNOPSIS
    检查 Node.js 是否存在且版本不低于指定主版本。
    #>
    [CmdletBinding()]
    param(
        [string]$NodePath,
        [int]$MinimumMajor = 24
    )

    $resolved = $null
    if (-not [string]::IsNullOrWhiteSpace($NodePath)) {
        $expanded = [Environment]::ExpandEnvironmentVariables($NodePath)
        if (Test-Path -LiteralPath $expanded -PathType Leaf) {
            $resolved = [System.IO.Path]::GetFullPath($expanded)
        }
        else {
            $resolved = Resolve-ExternalCommand -Name $NodePath -PreferredExtensions @('.exe')
        }
    }
    else {
        $resolved = Resolve-ExternalCommand -Name 'node' -PreferredExtensions @('.exe')
    }

    if (-not $resolved) {
        return [pscustomobject]@{
            Ok      = $false
            Path    = $null
            Version = $null
            Major   = $null
            Message = '未找到 Node.js（node.exe）'
        }
    }

    $result = Invoke-NativeCapture -FilePath $resolved -ArgumentList @('--version')
    $raw = $result.Output.Trim()
    if ($result.ExitCode -ne 0) {
        return [pscustomobject]@{
            Ok      = $false
            Path    = $resolved
            Version = $null
            Major   = $null
            Message = "无法运行 node --version（退出码 $($result.ExitCode)）：$raw"
        }
    }

    $versionText = $raw.TrimStart('v', 'V')
    $major = $null
    try {
        $major = [int]($versionText.Split('.')[0])
    }
    catch {
        $major = $null
    }

    if ($null -eq $major) {
        return [pscustomobject]@{
            Ok      = $false
            Path    = $resolved
            Version = $raw
            Major   = $null
            Message = "无法解析 Node.js 版本：$raw"
        }
    }

    if ($major -lt $MinimumMajor) {
        return [pscustomobject]@{
            Ok      = $false
            Path    = $resolved
            Version = $raw
            Major   = $major
            Message = "Node.js 版本过低：$raw（要求 >= $MinimumMajor）"
        }
    }

    return [pscustomobject]@{
        Ok      = $true
        Path    = $resolved
        Version = $raw
        Major   = $major
        Message = "Node.js $raw"
    }
}

function Get-McpRegistration {
    <#
    .SYNOPSIS
    读取 Claude Code 中指定 MCP server 的注册信息（只读）。
    #>
    [CmdletBinding()]
    param(
        [string]$Name = 'remote-mcp',
        [string]$ClaudePath
    )

    if ([string]::IsNullOrWhiteSpace($ClaudePath)) {
        $ClaudePath = Resolve-ExternalCommand -Name 'claude' -PreferredExtensions @('.cmd', '.exe')
    }

    if ([string]::IsNullOrWhiteSpace($ClaudePath) -or -not (Test-Path -LiteralPath $ClaudePath)) {
        return [pscustomobject]@{
            Available = $false
            Exists    = $false
            Name      = $Name
            Scope     = $null
            Command   = $null
            Args      = @()
            ArgsLine  = $null
            Status    = $null
            Connected = $false
            Raw       = $null
            ExitCode  = $null
            Error     = 'claude_not_found'
        }
    }

    $result = Invoke-NativeCapture -FilePath $ClaudePath -ArgumentList @('mcp', 'get', $Name)
    $raw = $result.Output
    $clean = [regex]::Replace($raw, "$([char]27)\[[0-9;?]*[A-Za-z]", '')

    $scope = $null
    $command = $null
    $argsLine = $null
    $status = $null

    $scopeMatch = [regex]::Match($clean, '(?im)^\s*Scope\s*:\s*(.+?)\s*$')
    if ($scopeMatch.Success) {
        $scopeText = $scopeMatch.Groups[1].Value
        if ($scopeText -match '(?i)\buser\b') { $scope = 'user' }
        elseif ($scopeText -match '(?i)\blocal\b') { $scope = 'local' }
        elseif ($scopeText -match '(?i)\bproject\b') { $scope = 'project' }
    }

    $commandMatch = [regex]::Match($clean, '(?im)^\s*Command\s*:\s*(.*?)\s*$')
    if ($commandMatch.Success) { $command = $commandMatch.Groups[1].Value }

    $argsMatch = [regex]::Match($clean, '(?im)^\s*Args\s*:\s*(.*?)\s*$')
    if ($argsMatch.Success) { $argsLine = $argsMatch.Groups[1].Value }

    $statusMatch = [regex]::Match($clean, '(?im)^\s*Status\s*:\s*(.*?)\s*$')
    if ($statusMatch.Success) { $status = $statusMatch.Groups[1].Value }

    $exists = ($result.ExitCode -eq 0) -and (-not [string]::IsNullOrWhiteSpace($command))
    $connected = $false
    if ($exists -and $status) {
        $connected = ($status -match '(?i)connected') -and ($status -notmatch '(?i)failed|error|not connected')
    }

    $argArray = @()
    if ($exists -and $null -ne $argsLine) {
        $argArray = @(ConvertFrom-QuotedArgLine -Line $argsLine)
    }

    $errorText = $null
    if (-not $exists) {
        if ($result.ExitCode -eq 0) { $errorText = 'not_found' }
        else { $errorText = "exit_$($result.ExitCode)" }
    }

    return [pscustomobject]@{
        Available = $true
        Exists    = $exists
        Name      = $Name
        Scope     = $scope
        Command   = $command
        Args      = $argArray
        ArgsLine  = $argsLine
        Status    = $status
        Connected = $connected
        Raw       = $clean
        ExitCode  = $result.ExitCode
        Error     = $errorText
    }
}

function Test-McpRegistrationMatch {
    <#
    .SYNOPSIS
    比较现有注册是否与期望的 Command/Args/Scope 一致（内部也用于幂等判断）。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Registration,
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$CliPath,
        [string]$ConfigPath,
        [string]$Scope = 'user'
    )

    if ($null -eq $Registration -or -not $Registration.Exists) { return $false }
    if (-not $Registration.Scope -or $Registration.Scope -ne $Scope) { return $false }

    $expectedCommand = [System.IO.Path]::GetFullPath($NodePath)
    $actualCommand = Normalize-ComparisonText $Registration.Command
    $expectedCommandText = Normalize-ComparisonText $expectedCommand
    if (-not [string]::Equals($actualCommand, $expectedCommandText, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }

    $expectedArgs = @([System.IO.Path]::GetFullPath($CliPath))
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        $expectedArgs += @('--config', [System.IO.Path]::GetFullPath($ConfigPath))
    }

    return Test-ArgListsMatch -Actual @($Registration.Args) -Expected $expectedArgs -ActualLine $Registration.ArgsLine -ExpectedLineSource $expectedArgs
}

function Set-McpRegistration {
    <#
    .SYNOPSIS
    以 user scope 注册 remote-mcp；注册失败时尽力恢复旧注册。
    #>
    [CmdletBinding()]
    param(
        [string]$Name = 'remote-mcp',
        [string]$Scope = 'user',
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$CliPath,
        [string]$ConfigPath,
        [string]$ClaudePath,
        [switch]$DryRun
    )

    if ([string]::IsNullOrWhiteSpace($ClaudePath)) {
        $ClaudePath = Resolve-ExternalCommand -Name 'claude' -PreferredExtensions @('.cmd', '.exe')
    }
    if ([string]::IsNullOrWhiteSpace($ClaudePath)) {
        return [pscustomobject]@{
            Ok          = $false
            Changed     = $false
            WouldChange = $false
            Restored    = $false
            Message     = '未找到 claude 命令'
            Current     = $null
            New         = $null
        }
    }

    $current = Get-McpRegistration -Name $Name -ClaudePath $ClaudePath
    $matches = Test-McpRegistrationMatch -Registration $current -NodePath $NodePath -CliPath $CliPath -ConfigPath $ConfigPath -Scope $Scope

    $expectedArgs = @([System.IO.Path]::GetFullPath($CliPath))
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        $expectedArgs += @('--config', [System.IO.Path]::GetFullPath($ConfigPath))
    }

    if ($matches) {
        return [pscustomobject]@{
            Ok          = $true
            Changed     = $false
            WouldChange = $false
            Restored    = $false
            Message     = '注册已是最新'
            Current     = $current
            New         = $current
        }
    }

    if ($DryRun) {
        return [pscustomobject]@{
            Ok          = $true
            Changed     = $false
            WouldChange = $true
            Restored    = $false
            Message     = '将更新 MCP 注册'
            Current     = $current
            New         = $null
            ExpectedArgs = $expectedArgs
        }
    }

    $oldScope = $Scope
    if ($current.Exists -and $current.Scope) { $oldScope = $current.Scope }

    if ($current.Exists) {
        $removeArgs = @('mcp', 'remove', $Name, '-s', $oldScope)
        $remove = Invoke-NativeCapture -FilePath $ClaudePath -ArgumentList $removeArgs
        if ($remove.ExitCode -ne 0) {
            return [pscustomobject]@{
                Ok          = $false
                Changed     = $false
                WouldChange = $false
                Restored    = $false
                Message     = "移除旧注册失败（退出码 $($remove.ExitCode)）：$($remove.Output)"
                Current     = $current
                New         = $null
            }
        }
    }

    $addArgs = @('mcp', 'add', $Name, '-s', $Scope, '--', [System.IO.Path]::GetFullPath($NodePath)) + $expectedArgs
    $add = Invoke-NativeCapture -FilePath $ClaudePath -ArgumentList $addArgs

    if ($add.ExitCode -ne 0) {
        $restored = $false
        $restoreMessage = ''
        if ($current.Exists -and -not [string]::IsNullOrWhiteSpace($current.Command)) {
            $restoreArgs = @('mcp', 'add', $Name, '-s', $oldScope, '--', $current.Command)
            if ($current.Args) { $restoreArgs += @($current.Args) }
            $restore = Invoke-NativeCapture -FilePath $ClaudePath -ArgumentList $restoreArgs
            $restored = ($restore.ExitCode -eq 0)
            if (-not $restored) {
                $restoreMessage = "；恢复旧注册也失败（退出码 $($restore.ExitCode)）：$($restore.Output)"
            }
        }

        return [pscustomobject]@{
            Ok          = $false
            Changed     = $true
            WouldChange = $false
            Restored    = $restored
            Message     = "注册失败（退出码 $($add.ExitCode)）：$($add.Output)$restoreMessage"
            Current     = $current
            New         = (Get-McpRegistration -Name $Name -ClaudePath $ClaudePath)
        }
    }

    $new = Get-McpRegistration -Name $Name -ClaudePath $ClaudePath
    $verified = Test-McpRegistrationMatch -Registration $new -NodePath $NodePath -CliPath $CliPath -ConfigPath $ConfigPath -Scope $Scope

    return [pscustomobject]@{
        Ok          = $verified
        Changed     = $true
        WouldChange = $false
        Restored    = $false
        Message     = $(if ($verified) { '注册已更新' } else { '注册命令执行成功，但回读结果与期望不一致' })
        Current     = $current
        New         = $new
        ExpectedArgs = $expectedArgs
    }
}

function Remove-McpRegistration {
    <#
    .SYNOPSIS
    移除指定 MCP server 的注册（默认从实际存在的 scope 移除）。
    #>
    [CmdletBinding()]
    param(
        [string]$Name = 'remote-mcp',
        [string]$ClaudePath,
        [switch]$DryRun
    )

    if ([string]::IsNullOrWhiteSpace($ClaudePath)) {
        $ClaudePath = Resolve-ExternalCommand -Name 'claude' -PreferredExtensions @('.cmd', '.exe')
    }
    if ([string]::IsNullOrWhiteSpace($ClaudePath)) {
        return [pscustomobject]@{
            Ok          = $false
            Removed     = $false
            WouldRemove = $false
            Exists      = $false
            Message     = '未找到 claude 命令'
            Registration = $null
        }
    }

    $current = Get-McpRegistration -Name $Name -ClaudePath $ClaudePath
    if (-not $current.Exists) {
        return [pscustomobject]@{
            Ok          = $true
            Removed     = $false
            WouldRemove = $false
            Exists      = $false
            Message     = '未注册'
            Registration = $current
        }
    }

    if ($DryRun) {
        return [pscustomobject]@{
            Ok          = $true
            Removed     = $false
            WouldRemove = $true
            Exists      = $true
            Message     = "将从 scope=$($current.Scope) 移除"
            Registration = $current
        }
    }

    $removeArgs = @('mcp', 'remove', $Name)
    if ($current.Scope) { $removeArgs += @('-s', $current.Scope) }
    $remove = Invoke-NativeCapture -FilePath $ClaudePath -ArgumentList $removeArgs
    $after = Get-McpRegistration -Name $Name -ClaudePath $ClaudePath

    return [pscustomobject]@{
        Ok          = (($remove.ExitCode -eq 0) -and (-not $after.Exists))
        Removed     = (-not $after.Exists)
        WouldRemove = $false
        Exists      = $after.Exists
        Message     = $(if (-not $after.Exists) { '注册已移除' } else { "移除失败（退出码 $($remove.ExitCode)）：$($remove.Output)" })
        Registration = $after
    }
}

function Initialize-RemoteMcpConfig {
    <#
    .SYNOPSIS
    复制配置样例，并在缺少 config.yaml 时从样例生成（永不覆盖已有配置）。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Context,
        [string]$ConfigPath,
        [string]$ConfigDir,
        [string]$ExamplePath,
        [switch]$NoConfig,
        [switch]$DryRun
    )

    if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath = $Context.ConfigPath }
    if ([string]::IsNullOrWhiteSpace($ConfigDir)) { $ConfigDir = $Context.ConfigDir }
    if ([string]::IsNullOrWhiteSpace($ExamplePath)) { $ExamplePath = $Context.ConfigExamplePath }

    $ConfigPath = [System.IO.Path]::GetFullPath($ConfigPath)
    $ConfigDir = [System.IO.Path]::GetFullPath($ConfigDir)
    $ExamplePath = [System.IO.Path]::GetFullPath($ExamplePath)

    if (-not (Test-Path -LiteralPath $ExamplePath -PathType Leaf)) {
        return [pscustomobject]@{
            Ok             = $false
            ConfigPath     = $ConfigPath
            ConfigCreated  = $false
            ExampleCopied  = $false
            ExampleNewPath = $null
            Message        = "缺少配置样例：$ExamplePath"
        }
    }

    $exampleTarget = Join-Path $ConfigDir 'config.example.yaml'
    $exampleNewPath = "$exampleTarget.new"
    $exampleCopied = $false
    $exampleStatus = 'skip'
    $exampleMessage = '配置样例已是最新'

    if (-not (Test-Path -LiteralPath $exampleTarget -PathType Leaf)) {
        $exampleStatus = 'copy'
        $exampleMessage = "将复制配置样例到 $exampleTarget"
        if (-not $DryRun) {
            if (-not (Test-Path -LiteralPath $ConfigDir)) {
                New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
            }
            Copy-Item -LiteralPath $ExamplePath -Destination $exampleTarget -Force
            $exampleCopied = $true
        }
    }
    else {
        $sourceHash = Get-FileSha256 -Path $ExamplePath
        $targetHash = Get-FileSha256 -Path $exampleTarget
        if ($sourceHash -and $targetHash -and -not [string]::Equals($sourceHash, $targetHash, [System.StringComparison]::OrdinalIgnoreCase)) {
            $exampleStatus = 'new'
            $exampleMessage = "配置样例有更新，将写入 $exampleNewPath（不覆盖已有文件）"
            if (-not $DryRun) {
                Copy-Item -LiteralPath $ExamplePath -Destination $exampleNewPath -Force
            }
        }
    }

    $configCreated = $false
    $configStatus = 'skip'
    $configMessage = '配置已存在，保持不变'

    if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
        $configStatus = 'existing'
    }
    elseif ($NoConfig) {
        $configStatus = 'noconfig'
        $configMessage = '按 -NoConfig 跳过生成配置'
    }
    else {
        $configStatus = 'create'
        $configMessage = "将从样例生成配置：$ConfigPath"
        if (-not $DryRun) {
            $configDirectory = Split-Path -Parent $ConfigPath
            if ($configDirectory -and -not (Test-Path -LiteralPath $configDirectory)) {
                New-Item -ItemType Directory -Force -Path $configDirectory | Out-Null
            }
            $exampleContent = [System.IO.File]::ReadAllText($ExamplePath, [System.Text.Encoding]::UTF8)
            $checkCommandLine = '#   校验：node scripts/check-config.mjs --config "' + $ConfigPath + '"'
            $header = @(
                '# ============================================================',
                '# 本文件由 install.ps1 从 config.example.yaml 生成。',
                '# hosts 中的示例主机（203.0.113.10 / deploy）和 default_host 必须替换为真实信息。',
                '# 修改后可用以下命令校验：',
                $checkCommandLine,
                '# ============================================================',
                ''
            ) -join [Environment]::NewLine
            [System.IO.File]::WriteAllText(
                $ConfigPath,
                $header + $exampleContent,
                (New-Object System.Text.UTF8Encoding($false))
            )
            $configCreated = $true
        }
    }

    return [pscustomobject]@{
        Ok             = $true
        ConfigPath     = $ConfigPath
        ConfigCreated  = $configCreated
        ConfigStatus   = $configStatus
        ExampleStatus  = $exampleStatus
        ExampleCopied  = $exampleCopied
        ExampleTarget  = $exampleTarget
        ExampleNewPath = $(if ($exampleStatus -eq 'new') { $exampleNewPath } else { $null })
        Message        = "$exampleMessage；$configMessage"
    }
}

function Invoke-NpmCi {
    <#
    .SYNOPSIS
    在仓库根目录执行 npm ci。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$NpmPath,
        [Parameter(Mandatory = $true)][string]$ProjectRoot,
        [string]$LogPath,
        [switch]$DryRun
    )

    if ($DryRun) {
        return [pscustomobject]@{ Ok = $true; ExitCode = 0; Output = ''; WouldRun = $true; Message = '将执行 npm ci' }
    }

    $result = Invoke-NativeCapture -FilePath $NpmPath -ArgumentList @('ci', '--no-audit', '--no-fund') -WorkingDirectory $ProjectRoot
    if ($LogPath) {
        Add-LogLine -Path $LogPath -Line "[npm ci] exit=$($result.ExitCode)"
        Add-LogLine -Path $LogPath -Line $result.Output
    }

    return [pscustomobject]@{
        Ok       = ($result.ExitCode -eq 0)
        ExitCode = $result.ExitCode
        Output   = $result.Output
        WouldRun = $false
        Message  = $(if ($result.ExitCode -eq 0) { 'npm ci 完成' } else { "npm ci 失败（退出码 $($result.ExitCode)）" })
    }
}

function Invoke-NpmBuild {
    <#
    .SYNOPSIS
    在仓库根目录执行 npm run build。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$NpmPath,
        [Parameter(Mandatory = $true)][string]$ProjectRoot,
        [string]$LogPath,
        [switch]$DryRun
    )

    if ($DryRun) {
        return [pscustomobject]@{ Ok = $true; ExitCode = 0; Output = ''; WouldRun = $true; Message = '将执行 npm run build' }
    }

    $result = Invoke-NativeCapture -FilePath $NpmPath -ArgumentList @('run', 'build') -WorkingDirectory $ProjectRoot
    if ($LogPath) {
        Add-LogLine -Path $LogPath -Line "[npm run build] exit=$($result.ExitCode)"
        Add-LogLine -Path $LogPath -Line $result.Output
    }

    return [pscustomobject]@{
        Ok       = ($result.ExitCode -eq 0)
        ExitCode = $result.ExitCode
        Output   = $result.Output
        WouldRun = $false
        Message  = $(if ($result.ExitCode -eq 0) { '构建完成' } else { "构建失败（退出码 $($result.ExitCode)）" })
    }
}

function Write-InstallState {
    <#
    .SYNOPSIS
    原子写入安装状态 JSON。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StatePath,
        [Parameter(Mandatory = $true)]$State,
        [string]$LogPath
    )

    try {
        $directory = Split-Path -Parent $StatePath
        if ($directory -and -not (Test-Path -LiteralPath $directory)) {
            New-Item -ItemType Directory -Force -Path $directory | Out-Null
        }
        $json = $State | ConvertTo-Json -Depth 8
        $temporary = "$StatePath.tmp.$PID"
        [System.IO.File]::WriteAllText($temporary, $json + [Environment]::NewLine, $script:Utf8NoBom)
        Move-Item -LiteralPath $temporary -Destination $StatePath -Force
        if ($LogPath) { Add-LogLine -Path $LogPath -Line "[state] $StatePath" }
        return [pscustomobject]@{ Ok = $true; Path = $StatePath; Message = '安装状态已写入' }
    }
    catch {
        return [pscustomobject]@{ Ok = $false; Path = $StatePath; Message = "写入安装状态失败：$($_.Exception.Message)" }
    }
}

function Read-InstallState {
    <#
    .SYNOPSIS
    读取安装状态；不存在或损坏时返回 $null。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StatePath
    )

    if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) { return $null }
    try {
        return (Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

function Remove-InstallState {
    <#
    .SYNOPSIS
    删除安装状态文件；目录为空时一并删除。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StatePath,
        [string]$LogPath
    )

    if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
        return [pscustomobject]@{ Ok = $true; Removed = $false; Message = '安装状态不存在' }
    }

    try {
        Remove-Item -LiteralPath $StatePath -Force
        $directory = Split-Path -Parent $StatePath
        if ($directory -and (Test-Path -LiteralPath $directory)) {
            $remaining = @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction SilentlyContinue)
            if ($remaining.Count -eq 0) {
                Remove-Item -LiteralPath $directory -Force -ErrorAction SilentlyContinue
            }
        }
        if ($LogPath) { Add-LogLine -Path $LogPath -Line "[state] removed $StatePath" }
        return [pscustomobject]@{ Ok = $true; Removed = $true; Message = '安装状态已删除' }
    }
    catch {
        return [pscustomobject]@{ Ok = $false; Removed = $false; Message = "删除安装状态失败：$($_.Exception.Message)" }
    }
}

function Get-DataDirSummary {
    <#
    .SYNOPSIS
    统计数据目录的文件数与总字节数（只读）。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{
            Exists     = $false
            Path       = $Path
            FileCount  = 0
            TotalBytes = 0
        }
    }

    $files = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue)
    $totalBytes = 0
    foreach ($file in $files) {
        $totalBytes += [long]$file.Length
    }

    return [pscustomobject]@{
        Exists     = $true
        Path       = $Path
        FileCount  = $files.Count
        TotalBytes = $totalBytes
    }
}

function Test-Elevated {
    <#
    .SYNOPSIS
    当前进程是否以管理员身份运行。
    #>
    [CmdletBinding()]
    param()

    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Write-Step {
    <#
    .SYNOPSIS
    统一打印 [OK]/[WOULD]/[SKIP]/[WARN]/[ERROR] 步骤行，可同时追加日志。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'OK', 'WOULD', 'SKIP', 'WARN', 'ERROR', 'STEP')]
        [string]$Tag = 'INFO',
        [string]$LogPath,
        [switch]$NoConsole
    )

    $line = "[$Tag] $Message"
    if (-not $NoConsole) {
        $color = 'Gray'
        switch ($Tag) {
            'OK' { $color = 'Green' }
            'WOULD' { $color = 'Cyan' }
            'SKIP' { $color = 'DarkGray' }
            'WARN' { $color = 'Yellow' }
            'ERROR' { $color = 'Red' }
            'STEP' { $color = 'White' }
        }
        Write-Host $line -ForegroundColor $color
    }

    if ($LogPath) {
        $timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
        Add-LogLine -Path $LogPath -Line "$timestamp $line"
    }
}

Export-ModuleMember -Function @(
    'Initialize-ConsoleEncoding',
    'Get-RemoteMcpContext',
    'Test-NodeRuntime',
    'Resolve-ExternalCommand',
    'Get-McpRegistration',
    'Set-McpRegistration',
    'Remove-McpRegistration',
    'Initialize-RemoteMcpConfig',
    'Invoke-NpmCi',
    'Invoke-NpmBuild',
    'Write-InstallState',
    'Read-InstallState',
    'Remove-InstallState',
    'Get-DataDirSummary',
    'Test-Elevated',
    'Write-Step'
)
