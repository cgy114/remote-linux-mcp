#Requires -Version 5.1
<#
.SYNOPSIS
remote-mcp 安装/升级脚本（Windows PowerShell 5.1）。

.DESCRIPTION
以 user scope 注册 MCP server，生成/校验配置，并在需要时安装依赖与构建。
-DryRun（或 -WhatIf）只做只读检查，不创建目录、不运行 npm、不注册、不写状态；
即使指定 -LogPath 也不写日志（DryRun 严格零写入）。

退出码：
  0 成功
  2 参数用法错误
  3 环境前置条件不满足（PowerShell / Node / npm / claude / ssh / 仓库文件）
  4 依赖安装、构建或 CLI 版本检查失败
  5 配置生成或校验失败
  6 MCP 注册更新失败
  7 MCP 健康检查未通过
  8 安装状态写入失败
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$DryRun,
    [string]$ConfigPath,
    [switch]$NoConfig,
    [switch]$SkipDeps,
    [switch]$ReinstallDeps,
    [switch]$SkipBuild,
    [switch]$SkipRegister,
    [switch]$NoVerify,
    [string]$NodePath,
    [string]$LogPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:IsDryRun = ($DryRun.IsPresent -or $WhatIfPreference)
# 只读 cmdlet（如 Get-FileHash）会响应 -WhatIf 并打印噪声；本脚本用自己的 IsDryRun 控制写操作。
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

function Exit-Install {
    param(
        [Parameter(Mandatory = $true)][int]$Code,
        [string]$Message
    )
    if (-not [string]::IsNullOrWhiteSpace($Message)) {
        Write-Step -Tag ERROR -Message $Message -LogPath $script:LogPath
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

function Get-HashOrNull {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        try {
            return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        }
        catch {
            return $null
        }
    }
    return $null
}

$modulePath = Join-Path $PSScriptRoot 'scripts\lib\RemoteMcp.Common.psm1'
if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    Write-Host "[ERROR] 缺少共享模块：$modulePath" -ForegroundColor Red
    exit 3
}
Import-Module -Name $modulePath -Force -DisableNameChecking
Initialize-ConsoleEncoding

# ---------------------------------------------------------------------------
# 参数与前置条件
# ---------------------------------------------------------------------------

if ($SkipDeps -and $ReinstallDeps) {
    Exit-Install -Code 2 -Message '-SkipDeps 与 -ReinstallDeps 不能同时使用。'
}
if (-not [string]::IsNullOrWhiteSpace($ConfigPath) -and (Test-Path -LiteralPath $ConfigPath -PathType Container)) {
    Exit-Install -Code 2 -Message '-ConfigPath 必须指向配置文件，而不是目录。'
}

$ctx = Get-RemoteMcpContext -ConfigPathOverride $ConfigPath

Write-Step -Tag INFO -Message "remote-mcp 安装程序 v$($ctx.Version)" -LogPath $script:LogPath
Write-Step -Tag INFO -Message "仓库：$($ctx.InstallRoot)" -LogPath $script:LogPath
if ($script:IsDryRun) {
    Write-Step -Tag WOULD -Message 'DryRun 模式：只做只读检查，不会修改任何文件或注册。' -LogPath $script:LogPath
    if ($script:RequestedLogPath) {
        Write-Step -Tag WOULD -Message "DryRun 不写日志，已忽略 -LogPath：$($script:RequestedLogPath)" -LogPath $script:LogPath
    }
}

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Exit-Install -Code 3 -Message "需要 Windows PowerShell 5.1 或更高版本，当前为 $($PSVersionTable.PSVersion)。"
}

if (Test-Elevated) {
    Write-Step -Tag WARN -Message '检测到管理员权限：安装只写当前用户目录，建议以普通用户运行，避免配置写入管理员账户。' -LogPath $script:LogPath
}
else {
    Write-Step -Tag WARN -Message '当前不是管理员：将以 user scope 安装，仅影响当前用户（无需提升权限）。' -LogPath $script:LogPath
}

$requiredFiles = @(
    $ctx.PackageJsonPath,
    $ctx.ConfigExamplePath,
    $ctx.CheckConfigPath,
    (Join-Path $ctx.InstallRoot 'package-lock.json')
)
foreach ($required in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        Exit-Install -Code 3 -Message "仓库文件缺失：$required"
    }
}
Write-Step -Tag OK -Message '仓库文件完整。' -LogPath $script:LogPath

$nodeInfo = Test-NodeRuntime -NodePath $NodePath -MinimumMajor 24
if (-not $nodeInfo.Ok) {
    Exit-Install -Code 3 -Message $nodeInfo.Message
}
Write-Step -Tag OK -Message "$($nodeInfo.Message)（$($nodeInfo.Path)）" -LogPath $script:LogPath

$npmPath = Resolve-ExternalCommand -Name 'npm' -PreferredExtensions @('.cmd')
if (-not $npmPath) {
    Exit-Install -Code 3 -Message '未找到 npm（npm.cmd）。请安装 Node.js 并确保 PATH 正确。'
}
Write-Step -Tag OK -Message "npm：$npmPath" -LogPath $script:LogPath

$claudePath = Resolve-ExternalCommand -Name 'claude' -PreferredExtensions @('.cmd', '.exe')
if (-not $claudePath) {
    Exit-Install -Code 3 -Message '未找到 claude 命令（claude.cmd）。请先安装 Claude Code。'
}
Write-Step -Tag OK -Message "claude：$claudePath" -LogPath $script:LogPath

$sshPath = Resolve-ExternalCommand -Name 'ssh' -PreferredExtensions @('.exe')
if (-not $sshPath) {
    Exit-Install -Code 3 -Message '未找到 ssh（ssh.exe）。请启用 Windows OpenSSH Client 或安装 Git for Windows。'
}
Write-Step -Tag OK -Message "ssh：$sshPath" -LogPath $script:LogPath

# ---------------------------------------------------------------------------
# 依赖与构建
# ---------------------------------------------------------------------------

function Test-DependenciesReady {
    $typescript = Join-Path $ctx.InstallRoot 'node_modules\typescript\package.json'
    $sdk = Join-Path $ctx.InstallRoot 'node_modules\@modelcontextprotocol\server\package.json'
    return ((Test-Path -LiteralPath $typescript -PathType Leaf) -and (Test-Path -LiteralPath $sdk -PathType Leaf))
}

function Test-BuildUpToDate {
    if (-not (Test-Path -LiteralPath $ctx.CliPath -PathType Leaf)) { return $false }
    $distTime = (Get-Item -LiteralPath $ctx.CliPath).LastWriteTimeUtc
    $inputs = New-Object System.Collections.Generic.List[object]

    if (Test-Path -LiteralPath $ctx.SrcRoot) {
        foreach ($file in @(Get-ChildItem -LiteralPath $ctx.SrcRoot -Recurse -File -ErrorAction SilentlyContinue)) {
            $inputs.Add($file)
        }
    }
    foreach ($inputPath in @($ctx.PackageJsonPath, $ctx.TsConfigPath)) {
        if (Test-Path -LiteralPath $inputPath -PathType Leaf) {
            $inputs.Add((Get-Item -LiteralPath $inputPath))
        }
    }

    foreach ($input in $inputs) {
        if ($input.LastWriteTimeUtc -gt $distTime) { return $false }
    }
    return $true
}

if ($SkipDeps) {
    Write-Step -Tag SKIP -Message '按 -SkipDeps 跳过依赖安装。' -LogPath $script:LogPath
}
elseif ((Test-DependenciesReady) -and (-not $ReinstallDeps)) {
    Write-Step -Tag SKIP -Message 'node_modules 已包含所需依赖，跳过 npm ci。' -LogPath $script:LogPath
}
else {
    if ($script:IsDryRun) {
        Write-Step -Tag WOULD -Message '将运行 npm ci。' -LogPath $script:LogPath
    }
    else {
        Write-Step -Tag STEP -Message '运行 npm ci ...' -LogPath $script:LogPath
        $npmCi = Invoke-NpmCi -NpmPath $npmPath -ProjectRoot $ctx.InstallRoot -LogPath $script:LogPath
        if (-not $npmCi.Ok) {
            Write-Step -Tag ERROR -Message $npmCi.Message -LogPath $script:LogPath
            Write-Host $npmCi.Output
            exit 4
        }
        Write-Step -Tag OK -Message $npmCi.Message -LogPath $script:LogPath
    }
}

if ($SkipBuild) {
    Write-Step -Tag SKIP -Message '按 -SkipBuild 跳过构建。' -LogPath $script:LogPath
}
elseif (Test-BuildUpToDate) {
    Write-Step -Tag SKIP -Message 'dist 已是最新，跳过 npm run build。' -LogPath $script:LogPath
}
else {
    if ($script:IsDryRun) {
        Write-Step -Tag WOULD -Message '将运行 npm run build。' -LogPath $script:LogPath
    }
    else {
        Write-Step -Tag STEP -Message '运行 npm run build ...' -LogPath $script:LogPath
        $build = Invoke-NpmBuild -NpmPath $npmPath -ProjectRoot $ctx.InstallRoot -LogPath $script:LogPath
        if (-not $build.Ok) {
            Write-Step -Tag ERROR -Message $build.Message -LogPath $script:LogPath
            Write-Host $build.Output
            exit 4
        }
        Write-Step -Tag OK -Message $build.Message -LogPath $script:LogPath
    }
}

if (-not (Test-Path -LiteralPath $ctx.CliPath -PathType Leaf)) {
    if ($script:IsDryRun) {
        Write-Step -Tag SKIP -Message 'dist/cli.js 尚未构建（DryRun 不执行构建）。' -LogPath $script:LogPath
    }
    else {
        Exit-Install -Code 4 -Message "构建后仍缺少 dist/cli.js：$($ctx.CliPath)"
    }
}
else {
    $versionOutput = & $nodeInfo.Path $ctx.CliPath --version 2>&1
    $versionCode = $LASTEXITCODE
    $versionText = Convert-NativeOutput $versionOutput
    if ($versionCode -ne 0) {
        Exit-Install -Code 4 -Message "node dist/cli.js --version 失败（退出码 $versionCode）：$versionText"
    }
    Write-Step -Tag OK -Message "CLI 可运行，版本 $versionText。" -LogPath $script:LogPath
    if (-not [string]::Equals($versionText, [string]$ctx.Version, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Step -Tag WARN -Message "CLI 版本（$versionText）与 package.json（$($ctx.Version)）不一致，请确认构建产物没有过期。" -LogPath $script:LogPath
    }
}

# ---------------------------------------------------------------------------
# 配置：先校验现有配置，再复制样例，最后按需生成（永不覆盖）
# ---------------------------------------------------------------------------

function Invoke-CheckConfig {
    param([Parameter(Mandatory = $true)][string]$Path)
    $output = & $nodeInfo.Path $ctx.CheckConfigPath --config $Path 2>&1
    $code = $LASTEXITCODE
    return [pscustomobject]@{
        ExitCode = $code
        Output   = (Convert-NativeOutput $output)
    }
}

$effectiveConfigPath = $ctx.ConfigPath
$configExistedBefore = Test-Path -LiteralPath $effectiveConfigPath -PathType Leaf
$configHashBefore = Get-HashOrNull -Path $effectiveConfigPath

if ($configExistedBefore) {
    $existingCheck = Invoke-CheckConfig -Path $effectiveConfigPath
    if ($existingCheck.ExitCode -eq 0) {
        Write-Step -Tag OK -Message "现有配置校验通过：$effectiveConfigPath" -LogPath $script:LogPath
    }
    else {
        Write-Step -Tag WARN -Message "现有配置校验失败（仅告警，不会覆盖）：$($existingCheck.Output)" -LogPath $script:LogPath
    }
}
elseif ($NoConfig) {
    Write-Step -Tag WARN -Message "配置不存在且指定了 -NoConfig；MCP 注册将指向不存在的配置，健康检查可能失败：$effectiveConfigPath" -LogPath $script:LogPath
}
else {
    Write-Step -Tag SKIP -Message "配置不存在，将在后续从样例生成：$effectiveConfigPath" -LogPath $script:LogPath
}

$configInit = Initialize-RemoteMcpConfig -Context $ctx -ConfigPath $effectiveConfigPath -NoConfig:$NoConfig -DryRun:$script:IsDryRun
if (-not $configInit.Ok) {
    Exit-Install -Code 5 -Message $configInit.Message
}

switch ($configInit.ExampleStatus) {
    'copy' {
        if ($script:IsDryRun) {
            Write-Step -Tag WOULD -Message "将复制配置样例到 $($configInit.ExampleTarget)。" -LogPath $script:LogPath
        }
        else {
            Write-Step -Tag OK -Message "配置样例已复制到 $($configInit.ExampleTarget)。" -LogPath $script:LogPath
        }
    }
    'new' {
        if ($script:IsDryRun) {
            Write-Step -Tag WOULD -Message "配置样例有更新，将写入 $($configInit.ExampleNewPath)（不覆盖旧样例）。" -LogPath $script:LogPath
        }
        else {
            Write-Step -Tag OK -Message "配置样例有更新，已写入 $($configInit.ExampleNewPath)（未覆盖旧样例）。" -LogPath $script:LogPath
        }
    }
    default {
        Write-Step -Tag SKIP -Message '配置样例已是最新。' -LogPath $script:LogPath
    }
}

switch ($configInit.ConfigStatus) {
    'existing' {
        Write-Step -Tag SKIP -Message "配置文件已存在，保持不变：$effectiveConfigPath" -LogPath $script:LogPath
    }
    'noconfig' {
        Write-Step -Tag SKIP -Message '按 -NoConfig 跳过配置生成。' -LogPath $script:LogPath
    }
    'create' {
        if ($script:IsDryRun) {
            Write-Step -Tag WOULD -Message "将从配置样例生成 $effectiveConfigPath。" -LogPath $script:LogPath
        }
        else {
            Write-Step -Tag OK -Message "已从配置样例生成 $effectiveConfigPath。" -LogPath $script:LogPath
            $generatedCheck = Invoke-CheckConfig -Path $effectiveConfigPath
            if ($generatedCheck.ExitCode -ne 0) {
                Exit-Install -Code 5 -Message "新生成的配置校验失败：$($generatedCheck.Output)"
            }
            Write-Step -Tag OK -Message '新生成的配置校验通过。' -LogPath $script:LogPath
        }
    }
}

if ($configExistedBefore) {
    $configHashAfter = Get-HashOrNull -Path $effectiveConfigPath
    if ($configHashBefore -and $configHashAfter -and -not [string]::Equals($configHashBefore, $configHashAfter, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Step -Tag WARN -Message '现有配置在安装过程中发生了变化，请检查是否有其他程序同时修改了配置。' -LogPath $script:LogPath
    }
}

# ---------------------------------------------------------------------------
# MCP 注册
# ---------------------------------------------------------------------------

if ($SkipRegister) {
    Write-Step -Tag SKIP -Message '按 -SkipRegister 跳过 MCP 注册。' -LogPath $script:LogPath
}
else {
    $registration = Set-McpRegistration `
        -Name $ctx.McpName `
        -Scope $ctx.Scope `
        -NodePath $nodeInfo.Path `
        -CliPath $ctx.CliPath `
        -ConfigPath $effectiveConfigPath `
        -ClaudePath $claudePath `
        -DryRun:$script:IsDryRun

    if ($script:IsDryRun) {
        if ($registration.WouldChange) {
            Write-Step -Tag WOULD -Message "将把 MCP 注册更新为：$($nodeInfo.Path) `"$($ctx.CliPath)`" --config `"$effectiveConfigPath`"" -LogPath $script:LogPath
        }
        else {
            Write-Step -Tag SKIP -Message 'MCP 注册的 Command/Args/Scope 已匹配，无需更新。' -LogPath $script:LogPath
        }
    }
    else {
        if (-not $registration.Ok) {
            Exit-Install -Code 6 -Message "MCP 注册失败：$($registration.Message)"
        }
        if ($registration.Changed) {
            Write-Step -Tag OK -Message 'MCP 注册已更新（user scope，绝对 node + dist/cli.js + --config）。' -LogPath $script:LogPath
        }
        else {
            Write-Step -Tag SKIP -Message 'MCP 注册已匹配，无需更新。' -LogPath $script:LogPath
        }
    }
}

# ---------------------------------------------------------------------------
# 健康检查
# ---------------------------------------------------------------------------

if ($script:IsDryRun) {
    Write-Step -Tag SKIP -Message 'DryRun 跳过 claude mcp list 健康检查。' -LogPath $script:LogPath
}
elseif ($SkipRegister) {
    Write-Step -Tag SKIP -Message '跳过了注册，跳过健康检查。' -LogPath $script:LogPath
}
elseif ($NoVerify) {
    Write-Step -Tag SKIP -Message '按 -NoVerify 跳过健康检查。' -LogPath $script:LogPath
}
else {
    $connected = $false
    $lastLine = $null
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $listOutput = & $claudePath mcp list 2>&1
        $listText = Convert-NativeOutput $listOutput
        $matchingLine = @($listText -split "\r?\n" | Where-Object {
            $_ -match ('(?i)^\s*' + [regex]::Escape($ctx.McpName) + '\s*:')
        }) | Select-Object -First 1

        if ($matchingLine) { $lastLine = $matchingLine }
        if ($matchingLine -and $matchingLine -match '(?i)connected' -and $matchingLine -notmatch '(?i)failed|error|not connected') {
            $connected = $true
            break
        }

        if ($attempt -lt 3) {
            Write-Step -Tag INFO -Message "第 $attempt 次健康检查尚未 Connected，2 秒后重试 ..." -LogPath $script:LogPath
            Start-Sleep -Seconds 2
        }
    }

    if (-not $connected) {
        if ($lastLine) {
            Exit-Install -Code 7 -Message "claude mcp list 未显示 Connected：$lastLine"
        }
        Exit-Install -Code 7 -Message 'claude mcp list 未找到 remote-mcp 或未显示 Connected。'
    }
    Write-Step -Tag OK -Message "claude mcp list：$lastLine" -LogPath $script:LogPath
}

# ---------------------------------------------------------------------------
# 安装状态
# ---------------------------------------------------------------------------

$state = [ordered]@{
    appVersion  = [string]$ctx.Version
    installRoot = [string]$ctx.InstallRoot
    nodePath    = [string]$nodeInfo.Path
    cliPath     = [string]$ctx.CliPath
    configPath  = [string]$effectiveConfigPath
    mcpName     = [string]$ctx.McpName
    scope       = [string]$ctx.Scope
    installedAt = [DateTime]::UtcNow.ToString('o')
}

if ($script:IsDryRun) {
    Write-Step -Tag WOULD -Message "将写入安装状态：$($ctx.StatePath)" -LogPath $script:LogPath
}
else {
    $stateResult = Write-InstallState -StatePath $ctx.StatePath -State $state -LogPath $script:LogPath
    if (-not $stateResult.Ok) {
        Exit-Install -Code 8 -Message $stateResult.Message
    }
    Write-Step -Tag OK -Message "$($stateResult.Message)：$($ctx.StatePath)" -LogPath $script:LogPath
}

# ---------------------------------------------------------------------------
# 下一步
# ---------------------------------------------------------------------------

Write-Host ''
Write-Step -Tag STEP -Message '下一步：' -LogPath $script:LogPath
Write-Host "  1. 编辑配置并替换示例主机：$effectiveConfigPath"
if (-not (Test-Path -LiteralPath $effectiveConfigPath -PathType Leaf) -and -not $NoConfig) {
    Write-Host '     （配置尚未创建；请重新运行安装或手动复制 config.example.yaml）'
}
Write-Host "  2. 固定主机密钥：node `"$($ctx.CliPath)`" trust <alias>"
Write-Host "  3. 如使用 sudo password 模式，写入密码：node `"$($ctx.CliPath)`" credential set <ref>"
Write-Host '  4. 重启 Claude Code，使 MCP 注册与配置生效。'

if ($script:IsDryRun) {
    Write-Step -Tag OK -Message 'DryRun 完成：未修改任何文件、注册或安装状态。' -LogPath $script:LogPath
}
else {
    Write-Step -Tag OK -Message '安装完成。' -LogPath $script:LogPath
}

exit 0
