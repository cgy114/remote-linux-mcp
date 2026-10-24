#Requires -Version 5.1
<#
.SYNOPSIS
remote-mcp 卸载脚本（Windows PowerShell 5.1）。

.DESCRIPTION
默认只移除 MCP 注册和安装状态，保留 ~/.remote-mcp 下的配置、信任记录与审计数据。
-RemoveData 会先做安全路径检查，再删除数据目录；非交互运行必须同时指定 -Yes。
数据目录的 basename 必须是 .remote-mcp；其他目录必须显式指定 -ForcePath。
-DryRun（或 -WhatIf）只做只读检查，即使指定 -LogPath 也不写日志（DryRun 严格零写入）。

退出码：
  0 成功
  2 参数用法错误或未确认删除
  3 数据目录安全校验失败
  4 MCP 注册移除失败
  5 安装状态或数据目录删除失败
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$DryRun,
    [switch]$RemoveData,
    [switch]$Yes,
    [string]$ConfigPath,
    [switch]$ForcePath,
    [string]$LogPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:IsDryRun = ($DryRun.IsPresent -or $WhatIfPreference)
# 只读 cmdlet 会响应 -WhatIf 并打印噪声；本脚本用自己的 IsDryRun 控制写操作。
$WhatIfPreference = $false

$script:LogPath = $null
$script:RequestedLogPath = $null
if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
    $resolvedLogPath = [System.IO.Path]::GetFullPath($LogPath)
    if (Test-Path -LiteralPath $resolvedLogPath -PathType Container) {
        Write-Host '[ERROR] -LogPath 必须指向文件，而不是目录。' -ForegroundColor Red
        exit 2
    }
    if ($script:IsDryRun) {
        # DryRun 严格零写入：只记录用户意图，不创建日志目录或文件。
        $script:RequestedLogPath = $resolvedLogPath
    }
    else {
        $script:LogPath = $resolvedLogPath
    }
}

function Exit-Uninstall {
    param(
        [Parameter(Mandatory = $true)][int]$Code,
        [string]$Message
    )
    if (-not [string]::IsNullOrWhiteSpace($Message)) {
        Write-Step -LogPath $script:LogPath -Tag ERROR -Message $Message
    }
    exit $Code
}

function Convert-NativeOutput {
    param($Output)
    return (($Output | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.ToString() }
        else { [string]$_ }
    }) -join [Environment]::NewLine).Trim()
}

function Get-NormalizedFullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($full)
    while ($full.Length -gt $root.Length -and ($full.EndsWith('\') -or $full.EndsWith('/'))) {
        $full = $full.Substring(0, $full.Length - 1)
    }
    return $full
}

function Test-PathEquals {
    param([string]$Left, [string]$Right)
    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) { return $false }
    return [string]::Equals(
        (Get-NormalizedFullPath $Left),
        (Get-NormalizedFullPath $Right),
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Test-IsStrictDescendant {
    param([string]$Child, [string]$Parent)
    $c = Get-NormalizedFullPath $Child
    $p = Get-NormalizedFullPath $Parent
    if ([string]::Equals($c, $p, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    if (-not $p.EndsWith('\')) { $p = $p + '\' }
    return $c.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-IsAncestorOf {
    param([string]$Ancestor, [string]$Descendant)
    return (Test-IsStrictDescendant -Child $Descendant -Parent $Ancestor)
}

function Get-ReparsePointHit {
    param([string]$Path)
    $current = Get-NormalizedFullPath $Path
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
            if ($item -and (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
                return $current
            }
        }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) { break }
        $current = $parent
    }
    return $null
}

function Find-ReparsePointUnder {
    param([string]$Root)
    $stack = New-Object System.Collections.Stack
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $directory = [string]$stack.Pop()
        try {
            $entries = [System.IO.Directory]::GetFileSystemEntries($directory)
        }
        catch {
            return [pscustomobject]@{ Found = $null; Error = $_.Exception.Message }
        }
        foreach ($entry in $entries) {
            try {
                $attributes = [System.IO.File]::GetAttributes($entry)
            }
            catch {
                return [pscustomobject]@{ Found = $null; Error = $_.Exception.Message }
            }
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                return [pscustomobject]@{ Found = $entry; Error = $null }
            }
            if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                $stack.Push($entry)
            }
        }
    }
    return [pscustomobject]@{ Found = $null; Error = $null }
}

function Get-CredentialRefs {
    param([string]$ConfigFile)
    if (-not (Test-Path -LiteralPath $ConfigFile -PathType Leaf)) { return @() }

    $text = [System.IO.File]::ReadAllText($ConfigFile, [System.Text.Encoding]::UTF8)
    $regex = [regex]'(?m)^\s*credential\s*:\s*(?:"([^"]+)"|''([^'']+)''|([^\s#]+))'
    $refs = New-Object System.Collections.Generic.List[string]
    foreach ($match in $regex.Matches($text)) {
        $value = $null
        if ($match.Groups[1].Success) { $value = $match.Groups[1].Value }
        elseif ($match.Groups[2].Success) { $value = $match.Groups[2].Value }
        else { $value = $match.Groups[3].Value }
        if (-not [string]::IsNullOrWhiteSpace($value) -and -not $refs.Contains($value)) {
            $refs.Add($value)
        }
    }
    return $refs.ToArray()
}

function Format-Bytes {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N2} GiB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N2} MiB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N2} KiB' -f ($Bytes / 1KB)) }
    return "$Bytes B"
}

function Test-SafeDataPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Context,
        [switch]$AllowOutsideHome
    )

    $errors = New-Object System.Collections.Generic.List[string]
    $full = Get-NormalizedFullPath $Path
    $driveRoot = [System.IO.Path]::GetPathRoot($full)

    # 数据目录名必须是 .remote-mcp；-ForcePath 同时用于确认非标准 basename。
    $leaf = Split-Path -Leaf $full
    if (-not $AllowOutsideHome -and -not [string]::Equals($leaf, '.remote-mcp', [System.StringComparison]::OrdinalIgnoreCase)) {
        $errors.Add("拒绝删除：数据目录 basename 必须是 .remote-mcp（当前：'$leaf'）；如确认安全，请追加 -ForcePath。")
    }

    if (Test-PathEquals $full $driveRoot) {
        $errors.Add('拒绝删除盘符根目录。')
    }
    if (Test-PathEquals $full $Context.HomeDir) {
        $errors.Add('拒绝删除用户主目录。')
    }
    if (Test-PathEquals $full $Context.InstallRoot) {
        $errors.Add('拒绝删除仓库根目录。')
    }
    if (Test-IsAncestorOf -Ancestor $full -Descendant $Context.HomeDir) {
        $errors.Add('拒绝删除用户主目录的上级目录。')
    }
    if (Test-IsAncestorOf -Ancestor $full -Descendant $Context.InstallRoot) {
        $errors.Add('拒绝删除仓库根目录的上级目录。')
    }

    $protected = @(
        (Join-Path $Context.HomeDir '.ssh'),
        (Join-Path $Context.HomeDir '.claude'),
        (Join-Path $Context.HomeDir '.gnupg'),
        (Join-Path $Context.HomeDir '.aws'),
        $Context.DistRoot,
        (Join-Path $Context.InstallRoot 'node_modules'),
        (Join-Path $Context.InstallRoot 'src'),
        (Join-Path $Context.InstallRoot '.git')
    )
    foreach ($item in $protected) {
        if (Test-PathEquals $full $item) {
            $errors.Add("拒绝删除受保护目录：$item")
        }
        elseif (Test-IsAncestorOf -Ancestor $full -Descendant $item) {
            $errors.Add("目标目录包含受保护目录：$item")
        }
        elseif (Test-IsStrictDescendant -Child $full -Parent $item) {
            $errors.Add("目标目录位于受保护目录内：$item")
        }
    }

    if (Test-Path -LiteralPath $full) {
        if (-not (Test-Path -LiteralPath $full -PathType Container)) {
            $errors.Add('目标路径存在但不是目录。')
        }
        $reparse = Get-ReparsePointHit -Path $full
        if ($reparse) {
            $errors.Add("目标目录或其上级是重解析点（符号链接/联接）：$reparse")
        }
        else {
            $nestedReparse = Find-ReparsePointUnder -Root $full
            if ($nestedReparse.Error) {
                $errors.Add("无法完整扫描数据目录，为避免误删已中止：$($nestedReparse.Error)")
            }
            elseif ($nestedReparse.Found) {
                $errors.Add("数据目录内部包含重解析点（符号链接/联接）：$($nestedReparse.Found)")
            }
        }
    }

    $underHome = Test-IsStrictDescendant -Child $full -Parent $Context.HomeDir
    $isHomeItself = Test-PathEquals $full $Context.HomeDir
    $isHomeAncestor = Test-IsAncestorOf -Ancestor $full -Descendant $Context.HomeDir
    if (-not $underHome -and -not $AllowOutsideHome -and -not $isHomeItself -and -not $isHomeAncestor) {
        $errors.Add('目标目录不在用户主目录下；如确认安全，请追加 -ForcePath。')
    }

    return [pscustomobject]@{
        Ok        = ($errors.Count -eq 0)
        FullPath  = $full
        UnderHome = $underHome
        Errors    = $errors.ToArray()
    }
}

# ---------------------------------------------------------------------------
# 环境与目标
# ---------------------------------------------------------------------------

$modulePath = Join-Path $PSScriptRoot 'scripts\lib\RemoteMcp.Common.psm1'
if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    Write-Host "[ERROR] 缺少共享模块：$modulePath" -ForegroundColor Red
    exit 3
}
Import-Module -Name $modulePath -Force -DisableNameChecking
Initialize-ConsoleEncoding

$ctx = Get-RemoteMcpContext -ConfigPathOverride $ConfigPath
$state = Read-InstallState -StatePath $ctx.StatePath

$effectiveConfigPath = $ctx.ConfigPath
if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
    $effectiveConfigPath = Get-NormalizedFullPath $ConfigPath
}
elseif ($state -and $state.PSObject.Properties['configPath'] -and -not [string]::IsNullOrWhiteSpace([string]$state.configPath)) {
    $effectiveConfigPath = Get-NormalizedFullPath ([string]$state.configPath)
}

$dataDir = Split-Path -Parent $effectiveConfigPath
if ([string]::IsNullOrWhiteSpace($dataDir)) {
    $dataDir = $ctx.ConfigDir
}
$dataDir = Get-NormalizedFullPath $dataDir

if ($Yes -and -not $RemoveData) {
    Write-Step -LogPath $script:LogPath -Tag WARN -Message '-Yes 只在与 -RemoveData 一起使用时生效。'
}

Write-Step -LogPath $script:LogPath -Tag INFO -Message 'remote-mcp 卸载程序'
Write-Step -LogPath $script:LogPath -Tag INFO -Message "仓库：$($ctx.InstallRoot)"
if ($script:IsDryRun) {
    Write-Step -LogPath $script:LogPath -Tag WOULD -Message 'DryRun 模式：只做只读检查，不会修改注册、状态或数据。'
    if ($script:RequestedLogPath) {
        Write-Step -LogPath $script:LogPath -Tag WOULD -Message "DryRun 不写日志，已忽略 -LogPath：$($script:RequestedLogPath)"
    }
}

$claudePath = Resolve-ExternalCommand -Name 'claude' -PreferredExtensions @('.cmd', '.exe')
$registration = $null
if ($claudePath) {
    $registration = Get-McpRegistration -Name $ctx.McpName -ClaudePath $claudePath
}

if (-not $claudePath) {
    Write-Step -LogPath $script:LogPath -Tag WARN -Message '未找到 claude 命令，无法检查或移除 MCP 注册。'
}
elseif ($registration -and $registration.Exists) {
    Write-Step -LogPath $script:LogPath -Tag INFO -Message "MCP 注册：已注册（scope=$($registration.Scope)，状态=$($registration.Status)）"
}
else {
    Write-Step -LogPath $script:LogPath -Tag SKIP -Message 'MCP 注册：未注册。'
}

if (Test-Path -LiteralPath $ctx.StatePath -PathType Leaf) {
    Write-Step -LogPath $script:LogPath -Tag INFO -Message "安装状态：$($ctx.StatePath)"
}
else {
    Write-Step -LogPath $script:LogPath -Tag SKIP -Message "安装状态：不存在（$($ctx.StatePath)）。"
}

$dataSummary = [pscustomobject]@{
    Exists     = (Test-Path -LiteralPath $dataDir)
    Path       = $dataDir
    FileCount  = 0
    TotalBytes = [long]0
}

# ---------------------------------------------------------------------------
# -RemoveData 的安全检查与确认
# ---------------------------------------------------------------------------

$safeDataPath = $null
if ($RemoveData) {
    # 先校验，且校验必须先于存在性判断：不存在的数据目录同样要检查 basename，
    # 否则 -ConfigPath 指向任意目录时会因“目录不存在”而绕过保护。
    # 先校验也避免对 C:\ 或用户主目录这类危险目标做全量统计。
    $safeDataPath = Test-SafeDataPath -Path $dataDir -Context $ctx -AllowOutsideHome:$ForcePath
    if (-not $safeDataPath.Ok) {
        foreach ($safetyError in $safeDataPath.Errors) {
            Write-Step -LogPath $script:LogPath -Tag ERROR -Message $safetyError
        }
        exit 3
    }
    Write-Step -LogPath $script:LogPath -Tag OK -Message "数据目录安全校验通过：$($safeDataPath.FullPath)"

    if ($dataSummary.Exists) {
        $dataSummary = Get-DataDirSummary -Path $dataDir
        Write-Step -LogPath $script:LogPath -Tag INFO -Message "数据目录：$dataDir（$($dataSummary.FileCount) 个文件，$(Format-Bytes $dataSummary.TotalBytes)）"

        if (-not $script:IsDryRun -and -not $Yes) {
            $interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
            if (-not $interactive) {
                Exit-Uninstall -Code 2 -Message '非交互环境删除数据必须显式指定 -Yes。'
            }
            $answer = Read-Host "将永久删除 $dataDir（$($dataSummary.FileCount) 个文件，$(Format-Bytes $dataSummary.TotalBytes)）。输入 YES 继续"
            if ($answer -ne 'YES') {
                Exit-Uninstall -Code 2 -Message '已取消：未删除任何数据。'
            }
        }
    }
    else {
        Write-Step -LogPath $script:LogPath -Tag SKIP -Message '数据目录不存在，无需删除。'
    }
}
elseif ($dataSummary.Exists) {
    if (Test-PathEquals $dataDir $ctx.ConfigDir) {
        $dataSummary = Get-DataDirSummary -Path $dataDir
        Write-Step -LogPath $script:LogPath -Tag INFO -Message "数据目录：$dataDir（$($dataSummary.FileCount) 个文件，$(Format-Bytes $dataSummary.TotalBytes)）"
    }
    else {
        Write-Step -LogPath $script:LogPath -Tag INFO -Message "数据目录：$dataDir（默认保留，未统计）"
    }
}
else {
    Write-Step -LogPath $script:LogPath -Tag SKIP -Message "数据目录：不存在（$dataDir）。"
}

# ---------------------------------------------------------------------------
# 移除 MCP 注册
# ---------------------------------------------------------------------------

if (-not $claudePath) {
    Write-Step -LogPath $script:LogPath -Tag WARN -Message '跳过 MCP 注册移除（未找到 claude）。'
}
elseif (-not $registration -or -not $registration.Exists) {
    Write-Step -LogPath $script:LogPath -Tag SKIP -Message 'MCP 注册不存在，跳过。'
}
elseif ($script:IsDryRun) {
    Write-Step -LogPath $script:LogPath -Tag WOULD -Message "将从 scope=$($registration.Scope) 移除 MCP 注册：$($ctx.McpName)"
}
else {
    $removeResult = Remove-McpRegistration -Name $ctx.McpName -ClaudePath $claudePath
    if (-not $removeResult.Ok) {
        Exit-Uninstall -Code 4 -Message "MCP 注册移除失败：$($removeResult.Message)"
    }
    if ($removeResult.Removed) {
        Write-Step -LogPath $script:LogPath -Tag OK -Message 'MCP 注册已移除。'
    }
    else {
        Write-Step -LogPath $script:LogPath -Tag SKIP -Message 'MCP 注册不存在，跳过。'
    }
}

# ---------------------------------------------------------------------------
# 移除安装状态
# ---------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $ctx.StatePath -PathType Leaf)) {
    Write-Step -LogPath $script:LogPath -Tag SKIP -Message '安装状态不存在，跳过。'
}
elseif ($script:IsDryRun) {
    Write-Step -LogPath $script:LogPath -Tag WOULD -Message "将删除安装状态：$($ctx.StatePath)"
}
else {
    $stateResult = Remove-InstallState -StatePath $ctx.StatePath
    if (-not $stateResult.Ok) {
        Exit-Uninstall -Code 5 -Message $stateResult.Message
    }
    Write-Step -LogPath $script:LogPath -Tag OK -Message $stateResult.Message
}

# ---------------------------------------------------------------------------
# 删除数据目录（可选）
# ---------------------------------------------------------------------------

if (-not $RemoveData) {
    Write-Step -LogPath $script:LogPath -Tag SKIP -Message "保留数据目录：$dataDir（配置、信任记录、审计数据均未删除）。"
}
elseif (-not $dataSummary.Exists) {
    Write-Step -LogPath $script:LogPath -Tag SKIP -Message '数据目录不存在，跳过删除。'
}
else {
    $credentialRefs = @(Get-CredentialRefs -ConfigFile $effectiveConfigPath)

    $nodeForCredential = $null
    if ($state -and $state.PSObject.Properties['nodePath'] -and -not [string]::IsNullOrWhiteSpace([string]$state.nodePath)) {
        $candidateNode = [string]$state.nodePath
        if (Test-Path -LiteralPath $candidateNode -PathType Leaf) { $nodeForCredential = $candidateNode }
    }
    if (-not $nodeForCredential) {
        $nodeCheck = Test-NodeRuntime -MinimumMajor 0
        if ($nodeCheck.Ok) { $nodeForCredential = $nodeCheck.Path }
    }

    $cliForCredential = $ctx.CliPath
    if ($state -and $state.PSObject.Properties['cliPath'] -and -not [string]::IsNullOrWhiteSpace([string]$state.cliPath)) {
        $candidateCli = [string]$state.cliPath
        if (Test-Path -LiteralPath $candidateCli -PathType Leaf) { $cliForCredential = $candidateCli }
    }
    if (-not (Test-Path -LiteralPath $cliForCredential -PathType Leaf)) {
        $cliForCredential = $null
    }

    if ($credentialRefs.Count -eq 0) {
        Write-Step -LogPath $script:LogPath -Tag SKIP -Message '配置中未发现 credential 引用。'
    }
    elseif (-not $nodeForCredential -or -not $cliForCredential) {
        Write-Step -LogPath $script:LogPath -Tag WARN -Message '无法调用 credential delete（缺少 node 或 dist/cli.js），请手动检查系统凭据库。'
    }
    else {
        foreach ($ref in $credentialRefs) {
            if ($script:IsDryRun) {
                Write-Step -LogPath $script:LogPath -Tag WOULD -Message "将尝试删除系统凭据：$ref"
                continue
            }
            $credentialOutput = & $nodeForCredential $cliForCredential credential delete $ref 2>&1
            $credentialCode = $LASTEXITCODE
            if ($credentialCode -eq 0) {
                Write-Step -LogPath $script:LogPath -Tag OK -Message "已删除系统凭据：$ref"
            }
            else {
                $credentialText = Convert-NativeOutput $credentialOutput
                Write-Step -LogPath $script:LogPath -Tag WARN -Message "删除系统凭据 $ref 未成功（退出码 $credentialCode）：$credentialText"
            }
        }
    }

    if ($script:IsDryRun) {
        Write-Step -LogPath $script:LogPath -Tag WOULD -Message "将删除数据目录：$dataDir（$($dataSummary.FileCount) 个文件，$(Format-Bytes $dataSummary.TotalBytes)）"
    }
    else {
        $recheck = Test-SafeDataPath -Path $dataDir -Context $ctx -AllowOutsideHome:$ForcePath
        if (-not $recheck.Ok) {
            foreach ($safetyError in $recheck.Errors) {
                Write-Step -LogPath $script:LogPath -Tag ERROR -Message $safetyError
            }
            exit 3
        }

        try {
            Remove-Item -LiteralPath $dataDir -Recurse -Force -ErrorAction Stop
        }
        catch {
            Exit-Uninstall -Code 5 -Message "删除数据目录失败：$($_.Exception.Message)"
        }

        if (Test-Path -LiteralPath $dataDir) {
            Exit-Uninstall -Code 5 -Message "删除后数据目录仍然存在：$dataDir"
        }
        Write-Step -LogPath $script:LogPath -Tag OK -Message "数据目录已删除：$dataDir"
    }
}

# ---------------------------------------------------------------------------
# 结束
# ---------------------------------------------------------------------------

Write-Host ''
if ($script:IsDryRun) {
    Write-Step -LogPath $script:LogPath -Tag OK -Message 'DryRun 完成：未修改注册、安装状态或数据。'
}
else {
    Write-Step -LogPath $script:LogPath -Tag OK -Message '卸载完成。'
    if (-not $RemoveData) {
        Write-Step -LogPath $script:LogPath -Tag INFO -Message "数据仍保留在 $dataDir；如需彻底删除，请重新运行并指定 -RemoveData -Yes。"
    }
    Write-Step -LogPath $script:LogPath -Tag INFO -Message '请重启 Claude Code，使已移除的 MCP server 从列表中消失。'
}

exit 0
