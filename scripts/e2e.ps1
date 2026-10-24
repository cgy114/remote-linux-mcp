#Requires -Version 5.1
<#
.SYNOPSIS
remote-mcp P6 端到端测试总控（Windows PowerShell 5.1）。

.DESCRIPTION
按层运行 Prerequisites / Build / Unit / Protocol / Real host / Container / VM，
每层输出 PASS / FAIL / SKIP，并在结束时打印汇总表；可用 -Json 输出机器可读报告。

- 默认行为：检查前置条件、构建、运行 unit + protocol；真实主机只在设置
  REMOTE_MCP_E2E=1 或显式 -Real 时运行；Docker 可用才尝试；Multipass 需要 -Multipass。
- -DryRun 不执行任何层，只打印计划执行的层与计划状态。
- -UnitOnly 只运行 unit + protocol，其余层 SKIP。
- 真实主机层使用 Vitest JSON reporter 解析计数，不依赖文本正则。
- 不修改远端、不执行卸载、不写入 ~/.remote-mcp。

退出码：
  0  所有已执行层 PASS 或 SKIP
  1  某个已执行层 FAIL（构建/测试/容器/VM）
  2  参数用法错误
  3  前置条件失败，或显式 -Real 时真实主机前置条件缺失
  4  报告写入失败
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$NoBuild,
    [switch]$UnitOnly,
    [switch]$NoReal,
    [switch]$Real,
    [string]$Alias = 'orangepi',
    [string]$ConfigPath,
    [switch]$NoContainers,
    [switch]$Multipass,
    [switch]$RequireContainers,
    [string]$TimeoutMin = '30',
    [switch]$Json,
    [string]$ReportPath,
    [switch]$Help
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($script:RepoRoot)) {
    $script:RepoRoot = (Get-Location).Path
}
$script:HumanOutput = -not $Json.IsPresent
$script:StartedAt = Get-Date
$script:Layers = New-Object System.Collections.ArrayList
$script:PrereqFailed = $false
$script:RealPrereqFailed = $false
$script:ResolvedConfigPath = $null
$script:NodeExe = $null
$script:NpmCli = $null

# ---------------------------------------------------------------------------
# 输出与参数错误
# ---------------------------------------------------------------------------

function Write-Human {
    param(
        [string]$Message = '',
        [string]$Color = 'Gray'
    )
    if ($script:HumanOutput) {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Exit-Usage {
    param([string]$Message)
    [Console]::Error.WriteLine("e2e.ps1: $Message")
    [Console]::Error.WriteLine('运行 powershell -NoProfile -ExecutionPolicy Bypass -File scripts/e2e.ps1 -Help 查看用法。')
    exit 2
}

function Show-Usage {
    @'
用法: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/e2e.ps1 [选项]

层:
  Prerequisites  检查 node>=24、npm、ssh、Vitest 与仓库文件
  Build          npm run build（-NoBuild 跳过）
  Unit           npx vitest run test/unit
  Protocol       npx vitest run test/protocol
  Real host      校验配置/alias/trust 后运行 test/integration
  Container      仅当 docker info 可用；在 Linux 容器中检查预检脚本与工具链
  VM             仅当显式 -Multipass 且 multipass 已安装

选项:
  -DryRun              只打印计划，不执行任何层
  -NoBuild             跳过构建（要求 dist/cli.js 已存在）
  -UnitOnly            只运行 Unit + Protocol
  -NoReal              即使设置了 REMOTE_MCP_E2E=1 也跳过真实主机
  -Real                显式要求真实主机层；前置条件缺失时 FAIL（退出码 3）
  -Alias <name>        真实主机 alias，默认 orangepi
                       同时设置 REMOTE_MCP_E2E_ALIAS
  -ConfigPath <path>   真实主机使用的配置；默认 REMOTE_MCP_CONFIG 或
                       ~/.remote-mcp/config.yaml
  -NoContainers        跳过 Container 层
  -Multipass           允许 VM 层（实例名固定为 remote-mcp-e2e）
  -RequireContainers   Docker 不可用时 Container 层 FAIL
  -TimeoutMin <n>      每层超时，默认 30 分钟（1-240）
  -Json                stdout 只输出 JSON 报告（人类可读输出被抑制）
  -ReportPath <file>   把 JSON 报告写入文件（UTF-8，无 BOM）

环境变量:
  REMOTE_MCP_E2E=1             等同于请求真实主机层
  REMOTE_MCP_E2E_ALIAS         测试读取的 alias（-Alias 会覆盖）
  REMOTE_MCP_E2E_FINGERPRINT   固定指纹的期望值（默认值见测试文件）
  REMOTE_MCP_CONFIG            配置路径（-ConfigPath 会覆盖）

退出码: 0 成功 / 1 层失败 / 2 用法错误 / 3 前置条件缺失 / 4 报告写入失败
'@ | Write-Host
}

# ---------------------------------------------------------------------------
# 参数校验
# ---------------------------------------------------------------------------

if ($Help.IsPresent) {
    Show-Usage
    exit 0
}

if ($Alias -notmatch '^[a-z0-9][a-z0-9._-]{0,63}$') {
    Exit-Usage "-Alias 必须匹配 ^[a-z0-9][a-z0-9._-]{0,63}$（收到: $Alias）"
}
[int]$timeoutValue = 0
if (-not [int]::TryParse($TimeoutMin, [ref]$timeoutValue) -or $timeoutValue -lt 1 -or $timeoutValue -gt 240) {
    Exit-Usage '-TimeoutMin 必须是 1 到 240 之间的整数'
}
$script:TimeoutMinutes = $timeoutValue
if ($Real.IsPresent -and $NoReal.IsPresent) {
    Exit-Usage '-Real 与 -NoReal 不能同时使用'
}
if ($UnitOnly.IsPresent -and $Real.IsPresent) {
    Exit-Usage '-UnitOnly 与 -Real 不能同时使用'
}
if ($NoContainers.IsPresent -and $RequireContainers.IsPresent) {
    Exit-Usage '-NoContainers 与 -RequireContainers 不能同时使用'
}
if ($UnitOnly.IsPresent -and $RequireContainers.IsPresent) {
    Exit-Usage '-UnitOnly 与 -RequireContainers 不能同时使用'
}
if ($UnitOnly.IsPresent -and $Multipass.IsPresent) {
    Exit-Usage '-UnitOnly 与 -Multipass 不能同时使用'
}
if (-not [string]::IsNullOrWhiteSpace($ConfigPath) -and (Test-Path -LiteralPath $ConfigPath -PathType Container)) {
    Exit-Usage "-ConfigPath 必须指向文件，而不是目录: $ConfigPath"
}
if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
    try {
        $reportFull = [System.IO.Path]::GetFullPath($ReportPath)
    } catch {
        Exit-Usage "-ReportPath 不是有效路径: $ReportPath"
    }
    if (Test-Path -LiteralPath $reportFull -PathType Container) {
        Exit-Usage "-ReportPath 必须指向文件，而不是目录: $ReportPath"
    }
    $script:ReportFullPath = $reportFull
} else {
    $script:ReportFullPath = $null
}

# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------

function ConvertTo-ProcessArgument {
    param([string]$Argument)
    if ($Argument -match '^[A-Za-z0-9_./:=+,@%^\-]+$') {
        return $Argument
    }
    $escaped = $Argument -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

function Stop-ProcessTree {
    param([int]$ProcessId)
    try {
        $taskkill = Get-Command taskkill.exe -ErrorAction SilentlyContinue
        if ($null -ne $taskkill) {
            & $taskkill.Source /PID $ProcessId /T /F 2>$null | Out-Null
            return
        }
    } catch {
        # 回退到单进程 Kill。
    }
    try {
        Get-Process -Id $ProcessId -ErrorAction Stop | Stop-Process -Force
    } catch {
        # 进程可能已退出。
    }
}

function Invoke-Process {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory = $script:RepoRoot,
        [int]$TimeoutMs = 120000
    )

    $result = [pscustomobject]@{
        ExitCode   = $null
        TimedOut   = $false
        StdOut     = ''
        StdErr     = ''
        DurationMs = 0
        Error      = $null
    }

    $started = Get-Date
    $process = $null
    $stdoutTask = $null
    $stderrTask = $null

    try {
        $argString = ($Arguments | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join ' '
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $FilePath
        $startInfo.Arguments = $argString
        $startInfo.WorkingDirectory = $WorkingDirectory
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw 'process did not start'
        }

        # 异步读取，避免子进程写满管道导致死锁。
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()

        if (-not $process.WaitForExit($TimeoutMs)) {
            $result.TimedOut = $true
            Stop-ProcessTree -ProcessId $process.Id
            try {
                $process.WaitForExit(5000) | Out-Null
            } catch {
                # 忽略等待失败。
            }
        } else {
            $process.WaitForExit()
        }

        try {
            $result.ExitCode = $process.ExitCode
        } catch {
            $result.ExitCode = $null
        }
    } catch {
        $result.Error = $_.Exception.Message
    } finally {
        if ($null -ne $stdoutTask) {
            try {
                $result.StdOut = $stdoutTask.Result
            } catch {
                $result.StdOut = ''
            }
        }
        if ($null -ne $stderrTask) {
            try {
                $result.StdErr = $stderrTask.Result
            } catch {
                $result.StdErr = ''
            }
        }
        if ($null -ne $process) {
            try {
                $process.Dispose()
            } catch {
                # 忽略释放失败。
            }
        }
        $result.DurationMs = [int]((Get-Date) - $started).TotalMilliseconds
    }

    return $result
}

$script:GitBashDir = $null
$script:GitBashProbed = $false

# 单元测试里的 “local bash simulation” 假设 `bash` 是 Git Bash；PowerShell 的 PATH
# 往往先解析到 WindowsApps 下的 WSL bash。仅在运行 Vitest 时把 Git 的 usr\bin
# 前置，不改动脚本自身或运行时解析 ssh 的逻辑。
function Get-GitBashDir {
    if ($script:GitBashProbed) {
        return $script:GitBashDir
    }
    $script:GitBashProbed = $true

    $gitCommand = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($null -eq $gitCommand) {
        return $null
    }
    $gitPath = $gitCommand.Source
    $gitRoot = $null
    if ($gitPath -match '^(.*)\\cmd\\git\.exe$') {
        $gitRoot = $Matches[1]
    } elseif ($gitPath -match '^(.*)\\mingw64\\bin\\git\.exe$') {
        $gitRoot = $Matches[1]
    }
    if ($null -eq $gitRoot) {
        return $null
    }
    $usrBin = Join-Path $gitRoot 'usr\bin'
    if (-not (Test-Path -LiteralPath (Join-Path $usrBin 'bash.exe') -PathType Leaf)) {
        return $null
    }
    $script:GitBashDir = $usrBin
    return $script:GitBashDir
}

function Get-OutputTail {
    param([string]$Text, [int]$MaxLength = 600)
    if ([string]::IsNullOrEmpty($Text)) {
        return ''
    }
    $trimmed = $Text.Trim()
    if ($trimmed.Length -le $MaxLength) {
        return $trimmed
    }
    return '...' + $trimmed.Substring($trimmed.Length - $MaxLength)
}

function Get-JsonNumber {
    param($Object, [string]$Name)
    if ($null -eq $Object) {
        return 0
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return 0
    }
    return [int]$property.Value
}

function New-LayerResult {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Status,
        [string]$Detail = '',
        [int]$DurationMs = 0,
        $Counts = $null,
        [string]$ErrorText = ''
    )
    return [pscustomobject]@{
        name       = $Name
        status     = $Status
        detail     = $Detail
        durationMs = $DurationMs
        counts     = $Counts
        error      = $ErrorText
    }
}

function Add-Layer {
    param($Layer)
    [void]$script:Layers.Add($Layer)
    $color = 'Gray'
    switch ($Layer.status) {
        'PASS' { $color = 'Green' }
        'FAIL' { $color = 'Red' }
        'SKIP' { $color = 'DarkGray' }
        'WOULD' { $color = 'Cyan' }
    }
    $seconds = [math]::Round($Layer.durationMs / 1000.0, 1)
    Write-Human ("[{0}] {1}: {2} ({3}s)" -f $Layer.status, $Layer.name, $Layer.detail, $seconds) $color
    if (($Layer.status -eq 'FAIL' -or $Layer.status -eq 'SKIP') -and
        -not [string]::IsNullOrWhiteSpace($Layer.error)) {
        Write-Human ("       " + (Get-OutputTail $Layer.error 800)) 'DarkYellow'
    }
}

function Get-FailureCount {
    $count = 0
    foreach ($layer in $script:Layers) {
        if ($layer.status -eq 'FAIL') {
            $count += 1
        }
    }
    return $count
}

function Get-StatusCount {
    param([string]$Status)
    $count = 0
    foreach ($layer in $script:Layers) {
        if ($layer.status -eq $Status) {
            $count += 1
        }
    }
    return $count
}

# ---------------------------------------------------------------------------
# 前置条件
# ---------------------------------------------------------------------------

$nodeCommand = Get-Command node.exe -ErrorAction SilentlyContinue
if ($null -eq $nodeCommand) {
    $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
}
if ($null -ne $nodeCommand) {
    $script:NodeExe = $nodeCommand.Source
    $candidateNpm = Join-Path (Split-Path -Parent $script:NodeExe) 'node_modules\npm\bin\npm-cli.js'
    if (Test-Path -LiteralPath $candidateNpm -PathType Leaf) {
        $script:NpmCli = $candidateNpm
    }
}
$script:VitestEntry = Join-Path $script:RepoRoot 'node_modules\vitest\vitest.mjs'

function Invoke-PrerequisitesLayer {
    $started = Get-Date
    if ($DryRun.IsPresent) {
        return New-LayerResult 'Prerequisites' 'WOULD' '检查 node>=24、npm、ssh、Vitest 与仓库文件'
    }

    $problems = @()
    $details = @()

    if ($null -eq $script:NodeExe) {
        $problems += 'node 不在 PATH'
    } else {
        $versionRun = Invoke-Process -FilePath $script:NodeExe -Arguments @('--version') -TimeoutMs 15000
        $versionText = $versionRun.StdOut.Trim()
        if ($versionRun.ExitCode -ne 0 -or $versionText -notmatch '^v(\d+)\.') {
            $reason = if ($null -ne $versionRun.Error) { $versionRun.Error } else { "exit=$($versionRun.ExitCode)" }
            $problems += "无法执行 node --version（$reason）"
        } else {
            $major = [int]$Matches[1]
            if ($major -lt 24) {
                $problems += "Node.js $versionText < 24"
            } else {
                $details += "Node $versionText"
            }
        }
    }

    if ($null -eq $script:NpmCli) {
        $problems += '未找到 npm-cli.js（无法运行 npm run build）'
    } else {
        $details += 'npm'
    }

    $sshCommand = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if ($null -eq $sshCommand) {
        $sshCommand = Get-Command ssh -ErrorAction SilentlyContinue
    }
    if ($null -eq $sshCommand) {
        $problems += 'ssh 不在 PATH'
    } else {
        $details += "ssh=$($sshCommand.Source)"
    }

    if (-not (Test-Path -LiteralPath $script:VitestEntry -PathType Leaf)) {
        $problems += 'node_modules/vitest/vitest.mjs 缺失（先运行 npm install）'
    } else {
        $details += 'Vitest'
    }

    $requiredFiles = @(
        'package.json',
        'vitest.config.ts',
        'scripts\check-config.mjs',
        'test\unit',
        'test\protocol',
        'test\integration'
    )
    foreach ($relative in $requiredFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $script:RepoRoot $relative))) {
            $problems += "缺少 $relative"
        }
    }

    $durationMs = [int]((Get-Date) - $started).TotalMilliseconds
    if ($problems.Count -gt 0) {
        return New-LayerResult 'Prerequisites' 'FAIL' ($problems -join '; ') $durationMs `
            $null ($problems -join [Environment]::NewLine)
    }
    return New-LayerResult 'Prerequisites' 'PASS' ($details -join ', ') $durationMs
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

function Invoke-BuildLayer {
    $started = Get-Date
    if ($DryRun.IsPresent) {
        if ($NoBuild.IsPresent) {
            return New-LayerResult 'Build' 'WOULD' '将检查 dist/cli.js（-NoBuild）'
        }
        return New-LayerResult 'Build' 'WOULD' '将运行 npm run build'
    }
    if ($UnitOnly.IsPresent) {
        return New-LayerResult 'Build' 'SKIP' '-UnitOnly：不构建'
    }
    if ($script:PrereqFailed) {
        return New-LayerResult 'Build' 'SKIP' '前置条件失败'
    }

    $distCli = Join-Path $script:RepoRoot 'dist\cli.js'
    if ($NoBuild.IsPresent) {
        if (Test-Path -LiteralPath $distCli -PathType Leaf) {
            return New-LayerResult 'Build' 'SKIP' '-NoBuild：使用现有 dist/cli.js'
        }
        $durationMs = [int]((Get-Date) - $started).TotalMilliseconds
        return New-LayerResult 'Build' 'FAIL' 'dist/cli.js 不存在，且指定了 -NoBuild' $durationMs `
            $null '先运行 npm run build，或去掉 -NoBuild。'
    }

    if ($null -eq $script:NpmCli) {
        $durationMs = [int]((Get-Date) - $started).TotalMilliseconds
        return New-LayerResult 'Build' 'FAIL' '无法定位 npm-cli.js' $durationMs $null '确认 Node.js/npm 安装完整。'
    }

    Write-Human '  $ node npm-cli.js run build' 'DarkGray'
    $run = Invoke-Process -FilePath $script:NodeExe `
        -Arguments @($script:NpmCli, 'run', 'build') `
        -TimeoutMs ($script:TimeoutMinutes * 60000)
    $durationMs = [int]((Get-Date) - $started).TotalMilliseconds

    if ($run.TimedOut) {
        return New-LayerResult 'Build' 'FAIL' "构建超时（$($script:TimeoutMinutes) 分钟）" $durationMs $null `
            (Get-OutputTail ($run.StdErr + [Environment]::NewLine + $run.StdOut))
    }
    if ($null -ne $run.Error) {
        return New-LayerResult 'Build' 'FAIL' "无法启动构建: $($run.Error)" $durationMs
    }
    if ($run.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $distCli -PathType Leaf)) {
        return New-LayerResult 'Build' 'FAIL' "构建失败（exit=$($run.ExitCode)）" $durationMs $null `
            (Get-OutputTail ($run.StdErr + [Environment]::NewLine + $run.StdOut))
    }
    return New-LayerResult 'Build' 'PASS' 'npm run build' $durationMs
}

# ---------------------------------------------------------------------------
# Vitest 层
# ---------------------------------------------------------------------------

function Read-VitestReport {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    try {
        $raw = [System.IO.File]::ReadAllText($Path)
        return ($raw | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Get-VitestCounts {
    param($Report)
    $skipped = (Get-JsonNumber $Report 'numPendingTests') + (Get-JsonNumber $Report 'numTodoTests')
    return [pscustomobject]@{
        files   = (Get-JsonNumber $Report 'numTotalTestSuites')
        total   = (Get-JsonNumber $Report 'numTotalTests')
        passed  = (Get-JsonNumber $Report 'numPassedTests')
        failed  = (Get-JsonNumber $Report 'numFailedTests')
        skipped = $skipped
    }
}

function Get-VitestFailureNames {
    param($Report)
    $names = @()
    if ($null -eq $Report) {
        return $names
    }
    $suites = $Report.PSObject.Properties['testResults']
    if ($null -eq $suites -or $null -eq $suites.Value) {
        return $names
    }
    foreach ($suite in @($suites.Value)) {
        $assertions = $suite.PSObject.Properties['assertionResults']
        if ($null -eq $assertions -or $null -eq $assertions.Value) {
            continue
        }
        foreach ($assertion in @($assertions.Value)) {
            if ($assertion.status -eq 'failed') {
                $name = [string]$assertion.fullName
                if ([string]::IsNullOrWhiteSpace($name)) {
                    $name = [string]$assertion.title
                }
                $names += $name
            }
        }
    }
    return $names
}

function Invoke-VitestLayer {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$TestPath
    )
    $started = Get-Date
    if ($DryRun.IsPresent) {
        return New-LayerResult $Name 'WOULD' "将运行 vitest run $TestPath"
    }
    if ($script:PrereqFailed) {
        return New-LayerResult $Name 'SKIP' '前置条件失败'
    }

    $reportFile = Join-Path ([System.IO.Path]::GetTempPath()) `
        ("remote-mcp-e2e-{0}-{1}.json" -f $Name, [Guid]::NewGuid().ToString('N'))
    Remove-Item -LiteralPath $reportFile -Force -ErrorAction SilentlyContinue

    $oldPath = $env:PATH
    try {
        $gitBash = Get-GitBashDir
        if ($null -ne $gitBash -and -not (($oldPath -split ';') -contains $gitBash)) {
            $env:PATH = $gitBash + ';' + $oldPath
            Write-Human "  (PATH 前置 $gitBash，使用 Git Bash)" 'DarkGray'
        }
        Write-Human "  `$ node vitest.mjs run $TestPath" 'DarkGray'
        $run = Invoke-Process -FilePath $script:NodeExe `
            -Arguments @($script:VitestEntry, 'run', $TestPath, '--reporter=json', "--outputFile=$reportFile") `
            -TimeoutMs ($script:TimeoutMinutes * 60000)
        $durationMs = [int]((Get-Date) - $started).TotalMilliseconds

        if ($run.TimedOut) {
            return New-LayerResult $Name 'FAIL' "超时（$($script:TimeoutMinutes) 分钟）" $durationMs $null `
                (Get-OutputTail ($run.StdErr + [Environment]::NewLine + $run.StdOut))
        }
        if ($null -ne $run.Error) {
            return New-LayerResult $Name 'FAIL' "无法启动 vitest: $($run.Error)" $durationMs
        }

        $report = Read-VitestReport $reportFile
        if ($null -eq $report) {
            return New-LayerResult $Name 'FAIL' "未生成可解析的 Vitest JSON 报告（exit=$($run.ExitCode)）" $durationMs $null `
                (Get-OutputTail ($run.StdErr + [Environment]::NewLine + $run.StdOut))
        }

        $counts = Get-VitestCounts $report
        $detail = "total=$($counts.total) passed=$($counts.passed) failed=$($counts.failed) skipped=$($counts.skipped)"

        if ($counts.total -eq 0) {
            return New-LayerResult $Name 'FAIL' "0 个测试被收集（$detail）" $durationMs $counts `
                (Get-OutputTail ($run.StdErr + [Environment]::NewLine + $run.StdOut))
        }
        if ($counts.failed -gt 0 -or $run.ExitCode -ne 0) {
            $failureNames = @(Get-VitestFailureNames $report)
            $failureText = ''
            if ($failureNames.Count -gt 0) {
                $shown = @($failureNames | Select-Object -First 10)
                $failureText = [Environment]::NewLine + '失败用例: ' + ($shown -join '; ')
                if ($failureNames.Count -gt $shown.Count) {
                    $failureText += "（另有 $($failureNames.Count - $shown.Count) 个）"
                }
            }
            return New-LayerResult $Name 'FAIL' "$detail (exit=$($run.ExitCode))" $durationMs $counts `
                ((Get-OutputTail ($run.StdErr + [Environment]::NewLine + $run.StdOut)) + $failureText)
        }
        return New-LayerResult $Name 'PASS' $detail $durationMs $counts
    } finally {
        $env:PATH = $oldPath
        Remove-Item -LiteralPath $reportFile -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# 真实主机
# ---------------------------------------------------------------------------

function Expand-UserPath {
    param([string]$PathValue)
    if ($PathValue -eq '~') {
        return $HOME
    }
    if ($PathValue.StartsWith('~/') -or $PathValue.StartsWith('~\')) {
        return (Join-Path $HOME $PathValue.Substring(2))
    }
    return $PathValue
}

function Resolve-E2eConfigPath {
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        return [System.IO.Path]::GetFullPath((Expand-UserPath $ConfigPath))
    }
    if (-not [string]::IsNullOrWhiteSpace($env:REMOTE_MCP_CONFIG)) {
        return [System.IO.Path]::GetFullPath((Expand-UserPath $env:REMOTE_MCP_CONFIG))
    }
    return [System.IO.Path]::GetFullPath((Join-Path $HOME '.remote-mcp\config.yaml'))
}

function Invoke-RealHostLayer {
    $started = Get-Date
    $requested = $Real.IsPresent -or ($env:REMOTE_MCP_E2E -eq '1')

    if ($UnitOnly.IsPresent) {
        return New-LayerResult 'Real host' 'SKIP' '-UnitOnly'
    }
    if ($NoReal.IsPresent) {
        return New-LayerResult 'Real host' 'SKIP' '-NoReal'
    }
    if (-not $requested) {
        $details = '未请求真实主机测试。请求方式: 设置 $env:REMOTE_MCP_E2E=1 后重跑，或使用 -Real；远端预检: bash scripts/ubuntu-preflight.sh'
        if ($DryRun.IsPresent) {
            return New-LayerResult 'Real host' 'SKIP' $details
        }
        return New-LayerResult 'Real host' 'SKIP' $details
    }

    $configFull = Resolve-E2eConfigPath
    $script:ResolvedConfigPath = $configFull

    if ($DryRun.IsPresent) {
        return New-LayerResult 'Real host' 'WOULD' `
            ("将校验 {0} 中 alias {1} 与 trust，然后运行 vitest run test/integration" -f $configFull, $Alias)
    }

    $problems = @()
    $hints = @()

    if (-not (Test-Path -LiteralPath $configFull -PathType Leaf)) {
        $problems += "配置文件不存在: $configFull"
        $hints += '先运行 install.ps1，或复制 config.example.yaml 并填写 hosts。'
    } else {
        # 1) alias 必须出现在 config.hosts 中。
        $aliasCheckCode = 'const fs=require("fs");const YAML=require("yaml");const a=process.argv.slice(1);let d;try{d=YAML.parse(fs.readFileSync(a[0],"utf8"))}catch(e){console.error("parse: "+e.message);process.exit(3)}process.exit(d&&d.hosts&&Object.prototype.hasOwnProperty.call(d.hosts,a[1])?0:4)'
        $aliasRun = Invoke-Process -FilePath $script:NodeExe `
            -Arguments @('-e', $aliasCheckCode, $configFull, $Alias) -TimeoutMs 30000
        if ($aliasRun.ExitCode -eq 4) {
            $problems += "配置中没有 host alias '$Alias'"
            $hints += "在 $configFull 的 hosts: 下添加 '$Alias'，或使用 -Alias 指定已有 alias。"
        } elseif ($aliasRun.ExitCode -eq 3) {
            $problems += "配置无法解析: $(Get-OutputTail $aliasRun.StdErr 300)"
            $hints += "运行 node scripts/check-config.mjs --config `"$configFull`" 查看详情。"
        } elseif ($aliasRun.ExitCode -ne 0) {
            $problems += "alias 检查失败（exit=$($aliasRun.ExitCode)）"
            $hints += (Get-OutputTail $aliasRun.StdErr 300)
        }

        # 2) 配置 schema 与 trust registry。
        $checkScript = Join-Path $script:RepoRoot 'scripts\check-config.mjs'
        $checkRun = Invoke-Process -FilePath $script:NodeExe `
            -Arguments @($checkScript, '--config', $configFull, '--require-trusted', $Alias, '--json') `
            -TimeoutMs 60000
        switch ($checkRun.ExitCode) {
            0 {
                # OK
            }
            4 {
                $problems += "alias '$Alias' 尚未受信任（trust registry 中没有固定密钥）"
                $hints += "node dist/cli.js trust $Alias"
            }
            3 {
                $problems += "配置校验失败: $(Get-OutputTail $checkRun.StdErr 300)"
                $hints += "node scripts/check-config.mjs --config `"$configFull`""
            }
            2 {
                $problems += "check-config 无法运行（dist 未构建或参数错误）"
                $hints += '先运行 npm run build（或去掉 -NoBuild）。'
            }
            default {
                $problems += "check-config 失败（exit=$($checkRun.ExitCode)）"
                $hints += (Get-OutputTail $checkRun.StdErr 300)
            }
        }
    }

    if ($problems.Count -gt 0) {
        $durationMs = [int]((Get-Date) - $started).TotalMilliseconds
        $detail = ($problems -join '; ')
        $message = ($problems + $hints) -join [Environment]::NewLine
        if ($Real.IsPresent) {
            $script:RealPrereqFailed = $true
            return New-LayerResult 'Real host' 'FAIL' $detail $durationMs $null $message
        }
        return New-LayerResult 'Real host' 'SKIP' $detail $durationMs $null $message
    }

    # 运行 integration 套件：通过环境变量传递 alias/config；指纹仍由测试的默认值或
    # 调用者已有的 REMOTE_MCP_E2E_FINGERPRINT 决定。
    $oldE2e = $env:REMOTE_MCP_E2E
    $oldAlias = $env:REMOTE_MCP_E2E_ALIAS
    $oldConfig = $env:REMOTE_MCP_CONFIG
    try {
        $env:REMOTE_MCP_E2E = '1'
        $env:REMOTE_MCP_E2E_ALIAS = $Alias
        $env:REMOTE_MCP_CONFIG = $configFull

        Write-Human "  `$ REMOTE_MCP_E2E=1 REMOTE_MCP_E2E_ALIAS=$Alias node vitest.mjs run test/integration" 'DarkGray'
        $layer = Invoke-VitestLayer -Name 'Real host' -TestPath 'test/integration'
        return $layer
    } finally {
        $env:REMOTE_MCP_E2E = $oldE2e
        $env:REMOTE_MCP_E2E_ALIAS = $oldAlias
        $env:REMOTE_MCP_CONFIG = $oldConfig
    }
}

# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------

function Invoke-ContainerLayer {
    $started = Get-Date
    if ($UnitOnly.IsPresent) {
        return New-LayerResult 'Container' 'SKIP' '-UnitOnly'
    }
    if ($NoContainers.IsPresent) {
        return New-LayerResult 'Container' 'SKIP' '-NoContainers'
    }
    if ($DryRun.IsPresent) {
        return New-LayerResult 'Container' 'WOULD' 'docker info 可用时在 ubuntu:24.04 容器中检查预检脚本'
    }

    $dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
    if ($null -eq $dockerCommand) {
        if ($RequireContainers.IsPresent) {
            $durationMs = [int]((Get-Date) - $started).TotalMilliseconds
            return New-LayerResult 'Container' 'FAIL' 'docker 未安装（-RequireContainers）' $durationMs
        }
        return New-LayerResult 'Container' 'SKIP' 'docker 未安装'
    }

    $infoRun = Invoke-Process -FilePath $dockerCommand.Source `
        -Arguments @('info', '--format', '{{.OSType}}') -TimeoutMs 30000
    if ($null -ne $infoRun.Error -or $infoRun.ExitCode -ne 0) {
        $detail = "docker info 不可用（exit=$($infoRun.ExitCode)）"
        $errorText = Get-OutputTail ($infoRun.StdErr + [Environment]::NewLine + $infoRun.StdOut)
        $durationMs = [int]((Get-Date) - $started).TotalMilliseconds
        if ($RequireContainers.IsPresent) {
            return New-LayerResult 'Container' 'FAIL' $detail $durationMs $null $errorText
        }
        return New-LayerResult 'Container' 'SKIP' $detail $durationMs $null $errorText
    }

    $osType = $infoRun.StdOut.Trim()
    if ($osType -ne 'linux') {
        $detail = "Docker 不是 Linux 容器模式（OSType=$osType）"
        $durationMs = [int]((Get-Date) - $started).TotalMilliseconds
        if ($RequireContainers.IsPresent) {
            return New-LayerResult 'Container' 'FAIL' $detail $durationMs
        }
        return New-LayerResult 'Container' 'SKIP' $detail $durationMs
    }

    $image = 'ubuntu:24.04'
    $inspectRun = Invoke-Process -FilePath $dockerCommand.Source `
        -Arguments @('image', 'inspect', $image) -TimeoutMs 30000
    if ($inspectRun.ExitCode -ne 0) {
        Write-Human "  `$ docker pull $image" 'DarkGray'
        $pullRun = Invoke-Process -FilePath $dockerCommand.Source `
            -Arguments @('pull', $image) -TimeoutMs 300000
        if ($pullRun.ExitCode -ne 0) {
            $detail = "镜像 $image 不可用，且拉取失败"
            $durationMs = [int]((Get-Date) - $started).TotalMilliseconds
            $errorText = Get-OutputTail ($pullRun.StdErr + [Environment]::NewLine + $pullRun.StdOut)
            if ($RequireContainers.IsPresent) {
                return New-LayerResult 'Container' 'FAIL' $detail $durationMs $null $errorText
            }
            return New-LayerResult 'Container' 'SKIP' $detail $durationMs $null $errorText
        }
    }

    $mount = "type=bind,source=$($script:RepoRoot),target=/repo,readonly"
    $inner = 'bash -n /repo/scripts/ubuntu-preflight.sh && command -v tar >/dev/null && command -v sha256sum >/dev/null && command -v stat >/dev/null && echo CONTAINER_OK'
    $run = Invoke-Process -FilePath $dockerCommand.Source `
        -Arguments @('run', '--rm', '--mount', $mount, '-w', '/repo', $image, 'bash', '-lc', $inner) `
        -TimeoutMs 180000
    $durationMs = [int]((Get-Date) - $started).TotalMilliseconds

    if ($run.TimedOut) {
        return New-LayerResult 'Container' 'FAIL' '容器执行超时' $durationMs $null `
            (Get-OutputTail ($run.StdErr + [Environment]::NewLine + $run.StdOut))
    }
    if ($run.ExitCode -ne 0 -or $run.StdOut -notmatch 'CONTAINER_OK') {
        return New-LayerResult 'Container' 'FAIL' "容器检查失败（exit=$($run.ExitCode)）" $durationMs $null `
            (Get-OutputTail ($run.StdErr + [Environment]::NewLine + $run.StdOut))
    }
    return New-LayerResult 'Container' 'PASS' "${image}: bash -n + tar/sha256sum/stat" $durationMs
}

# ---------------------------------------------------------------------------
# VM（Multipass）
# ---------------------------------------------------------------------------

function Invoke-VmLayer {
    $started = Get-Date
    if ($UnitOnly.IsPresent) {
        return New-LayerResult 'VM' 'SKIP' '-UnitOnly'
    }
    if (-not $Multipass.IsPresent) {
        return New-LayerResult 'VM' 'SKIP' '未指定 -Multipass'
    }
    if ($DryRun.IsPresent) {
        return New-LayerResult 'VM' 'WOULD' '将把预检脚本传到 multipass 实例 remote-mcp-e2e 并运行'
    }

    $multipassCommand = Get-Command multipass -ErrorAction SilentlyContinue
    if ($null -eq $multipassCommand) {
        return New-LayerResult 'VM' 'SKIP' 'multipass 未安装'
    }

    $instance = 'remote-mcp-e2e'
    $infoRun = Invoke-Process -FilePath $multipassCommand.Source `
        -Arguments @('info', $instance) -TimeoutMs 30000
    if ($infoRun.ExitCode -ne 0) {
        return New-LayerResult 'VM' 'SKIP' "实例 $instance 不存在；创建: multipass launch --name $instance 24.04"
    }

    $scriptPath = Join-Path $script:RepoRoot 'scripts\ubuntu-preflight.sh'
    $remotePath = '/tmp/remote-mcp-preflight.sh'
    $transferRun = Invoke-Process -FilePath $multipassCommand.Source `
        -Arguments @('transfer', $scriptPath, "${instance}:$remotePath") -TimeoutMs 120000
    if ($transferRun.ExitCode -ne 0) {
        $durationMs = [int]((Get-Date) - $started).TotalMilliseconds
        return New-LayerResult 'VM' 'FAIL' '预检脚本传输失败' $durationMs $null `
            (Get-OutputTail ($transferRun.StdErr + [Environment]::NewLine + $transferRun.StdOut))
    }

    try {
        $execRun = Invoke-Process -FilePath $multipassCommand.Source `
            -Arguments @('exec', $instance, '--', 'bash', $remotePath, '--json') -TimeoutMs 180000
        $durationMs = [int]((Get-Date) - $started).TotalMilliseconds
        if ($execRun.TimedOut -or $null -ne $execRun.Error) {
            return New-LayerResult 'VM' 'FAIL' '预检脚本执行失败' $durationMs $null `
                (Get-OutputTail ($execRun.StdErr + [Environment]::NewLine + $execRun.StdOut))
        }
        $preflight = $null
        try {
            $preflight = $execRun.StdOut | ConvertFrom-Json
        } catch {
            return New-LayerResult 'VM' 'FAIL' '预检脚本没有输出 JSON' $durationMs $null `
                (Get-OutputTail ($execRun.StdErr + [Environment]::NewLine + $execRun.StdOut))
        }
        $summary = $preflight.summary
        $detail = "preflight exit=$($preflight.summary.exitCode) ok=$($summary.ok) warn=$($summary.warn) fail=$($summary.fail) skip=$($summary.skip)"
        return New-LayerResult 'VM' 'PASS' $detail $durationMs $summary
    } finally {
        $cleanup = Invoke-Process -FilePath $multipassCommand.Source `
            -Arguments @('exec', $instance, '--', 'rm', '-f', $remotePath) -TimeoutMs 30000
        # 清理失败不影响层结果。
    }
}

# ---------------------------------------------------------------------------
# 执行
# ---------------------------------------------------------------------------

Write-Human 'remote-mcp E2E' 'White'
Write-Human ("repo={0} alias={1} timeout={2}min dryRun={3}" -f $script:RepoRoot, $Alias, $script:TimeoutMinutes, $DryRun.IsPresent) 'DarkGray'
Write-Human ''

$prereq = Invoke-PrerequisitesLayer
Add-Layer $prereq
if ($prereq.status -eq 'FAIL') {
    $script:PrereqFailed = $true
}

$build = Invoke-BuildLayer
Add-Layer $build

$unit = Invoke-VitestLayer -Name 'Unit' -TestPath 'test/unit'
Add-Layer $unit

$protocol = Invoke-VitestLayer -Name 'Protocol' -TestPath 'test/protocol'
Add-Layer $protocol

$realHost = Invoke-RealHostLayer
Add-Layer $realHost

$container = Invoke-ContainerLayer
Add-Layer $container

$vm = Invoke-VmLayer
Add-Layer $vm

# ---------------------------------------------------------------------------
# 汇总与报告
# ---------------------------------------------------------------------------

$finishedAt = Get-Date
$totalDurationMs = [int]($finishedAt - $script:StartedAt).TotalMilliseconds
$failCount = Get-FailureCount

if ($script:PrereqFailed -or $script:RealPrereqFailed) {
    $exitCode = 3
} elseif ($failCount -gt 0) {
    $exitCode = 1
} else {
    $exitCode = 0
}

if ($script:HumanOutput) {
    Write-Human ''
    Write-Human 'Layer            Status  Duration  Detail' 'White'
    Write-Human '---------------- ------  --------  ------' 'DarkGray'
    foreach ($layer in $script:Layers) {
        $seconds = [math]::Round($layer.durationMs / 1000.0, 1)
        $detail = $layer.detail
        if ($detail.Length -gt 100) {
            $detail = $detail.Substring(0, 97) + '...'
        }
        Write-Human ("{0,-16} {1,-6} {2,8}s  {3}" -f $layer.name, $layer.status, $seconds, $detail)
    }
    Write-Human ''
    Write-Human ("Summary: PASS={0} FAIL={1} SKIP={2} WOULD={3}  total={4:N1}s  exit={5}" -f `
        (Get-StatusCount 'PASS'), (Get-StatusCount 'FAIL'), (Get-StatusCount 'SKIP'), `
        (Get-StatusCount 'WOULD'), ($totalDurationMs / 1000.0), $exitCode) 'White'
}

$report = [ordered]@{
    schemaVersion = 1
    tool          = 'remote-mcp-e2e'
    startedAt     = $script:StartedAt.ToString('o')
    finishedAt    = $finishedAt.ToString('o')
    durationMs    = $totalDurationMs
    dryRun        = $DryRun.IsPresent
    repoRoot      = $script:RepoRoot
    alias         = $Alias
    configPath    = $script:ResolvedConfigPath
    exitCode      = $exitCode
    summary       = [ordered]@{
        pass  = (Get-StatusCount 'PASS')
        fail  = (Get-StatusCount 'FAIL')
        skip  = (Get-StatusCount 'SKIP')
        would = (Get-StatusCount 'WOULD')
    }
    layers        = @($script:Layers)
}
$jsonText = $report | ConvertTo-Json -Depth 8

if ($null -ne $script:ReportFullPath) {
    try {
        $directory = Split-Path -Parent $script:ReportFullPath
        if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -LiteralPath $directory)) {
            New-Item -ItemType Directory -Force -Path $directory | Out-Null
        }
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($script:ReportFullPath, $jsonText, $utf8NoBom)
        Write-Human "报告: $($script:ReportFullPath)" 'DarkGray'
    } catch {
        [Console]::Error.WriteLine("e2e.ps1: 无法写入报告 $($script:ReportFullPath): $($_.Exception.Message)")
        exit 4
    }
}

if ($Json.IsPresent) {
    Write-Output $jsonText
}

exit $exitCode
