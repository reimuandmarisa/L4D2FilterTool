# ci-local.ps1 --- 本地 / CI 共用的验证入口（P2：CI 与回归门禁）
#
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci-local.ps1        # 本地全量
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci-local.ps1 -Ci    # CI（不签名校验、不还原常驻）
#
# 步骤：preflight -> 原生组服 DLL（始终从源码构建）-> 原生 safe_regex 测试 -> 托管构建（SSF_NO_RESIDENT=1）-> 门禁
#       -> tests.ps1 -> supply-chain.ps1 -Check -> release.ps1 -Check -> harden-acl.ps1 -Check ->（仅本地）签名校验 + 还原常驻
# 退出码：0 = 全部通过；1 = 有失败（失败明细在末尾汇总）
param(
    [switch]$Ci,
    [switch]$SkipNative,
    [switch]$SkipRelease,
    [switch]$SkipAcl
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$script:results = New-Object System.Collections.ArrayList

function Add-Result([string]$name, [bool]$ok, [string]$note) {
    [void]$script:results.Add([pscustomobject]@{ Name = $name; Ok = $ok; Note = $note })
}

function Run-Step([string]$name, [scriptblock]$body) {
    Write-Host ''
    Write-Host ('== ' + $name + ' ==') -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $body
        $sw.Stop()
        Add-Result $name $true ('{0:N1}s' -f $sw.Elapsed.TotalSeconds)
        Write-Host ('[PASS] ' + $name) -ForegroundColor Green
    } catch {
        $sw.Stop()
        Add-Result $name $false ('' + $_.Exception.Message)
        Write-Host ('[FAIL] ' + $name + ': ' + $_.Exception.Message) -ForegroundColor Red
    }
}

function Expect-Exit([string]$what, [int]$code) {
    if ($code -ne 0) { throw ($what + ' 返回 ' + $code) }
}

function Invoke-Checked([string]$exePath, [string[]]$argv, [string]$label) {
    $out = & $exePath @argv 2>&1 | Out-String
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Write-Host $out
        throw ($label + ' 返回 ' + $code)
    }
    return $out
}

if ($Ci) {
    $SkipAcl = $true
    $env:SSF_NO_RESIDENT = '1'
}

Run-Step 'preflight' {
    foreach ($n in @('build.cmd', '_build', 'tools', 'tests.ps1', 'README.md', '_build\FilterTool.cs')) {
        if (-not (Test-Path (Join-Path $root $n))) { throw ('缺少 ' + $n) }
    }
}

Run-Step 'native groupfilter DLL (always built from source)' {
    $dll = Join-Path $root '_work\gf2\dist\SSF_GroupFilter2.dll'
    if ($SkipNative) {
        if (-not (Test-Path -LiteralPath $dll)) { throw '指定了 -SkipNative 但预构建原生 DLL 不存在' }
        Write-Host ('[SKIP] -SkipNative：使用预先存在的 ' + $dll)
        return
    }
    $nativeBuild = Join-Path $root '_work\gf2\build.cmd'
    if (-not (Test-Path -LiteralPath $nativeBuild)) { throw ('缺少原生工程：' + $nativeBuild) }
    Push-Location (Split-Path -Parent $nativeBuild)
    try { cmd /c build.cmd; $code = $LASTEXITCODE } finally { Pop-Location }
    Expect-Exit '原生 DLL 构建' $code
    if (-not (Test-Path -LiteralPath $dll)) { throw '原生构建结束但 DLL 不存在' }
}

Run-Step 'native safe_regex tests' {
    $t = Join-Path $root '_work\gf2\dist\test_safe_regex.exe'
    if (-not (Test-Path -LiteralPath $t)) { Write-Host ('[SKIP] 未找到原生测试目标：' + $t); return }
    & $t
    Expect-Exit 'test_safe_regex.exe' $LASTEXITCODE
}
Run-Step 'managed build (SSF_NO_RESIDENT=1)' {
    cmd /c build.cmd
    Expect-Exit 'build.cmd' $LASTEXITCODE
}

Run-Step 'gates: --layout / --selftest / --doc-check' {
    $exe = Join-Path $root 'FilterTool.exe'
    foreach ($a in @('--version', '--layout', '--selftest', '--doc-check')) {
        $out = Invoke-Checked $exe @($a) $a
        Write-Host (($out -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 3) -join ' | ')
    }
}

Run-Step 'tests.ps1' {
    powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'tests.ps1')
    Expect-Exit 'tests.ps1' $LASTEXITCODE
}

Run-Step 'supply-chain.ps1 -Check' {
    $sc = Join-Path $root 'tools\supply-chain.ps1'
    if (-not (Test-Path -LiteralPath $sc)) { throw '缺少 tools\supply-chain.ps1' }
    & $sc -Check
    Expect-Exit 'supply-chain.ps1 -Check' $LASTEXITCODE
}

if (-not $SkipRelease) {
    Run-Step 'release.ps1 -Check' {
        & (Join-Path $root 'tools\release.ps1') -Check
        Expect-Exit 'release.ps1 -Check' $LASTEXITCODE
    }
}

if (-not $SkipAcl) {
    Run-Step 'harden-acl.ps1 -Check' {
        & (Join-Path $root 'tools\harden-acl.ps1') -Check
        Expect-Exit 'harden-acl.ps1 -Check' $LASTEXITCODE
    }
}

if (-not $Ci) {
    Run-Step 'authenticode verify' {
        $sign = Join-Path $root 'tools\sign.ps1'
        if (-not (Test-Path -LiteralPath $sign)) { throw '缺少 tools\sign.ps1' }
        $exe = Join-Path $root 'FilterTool.exe'
        $sig = Get-AuthenticodeSignature -FilePath $exe
        if ($sig.Status -eq 'NotSigned') { Write-Host '[SKIP] FilterTool.exe 未签名（先跑 tools\sign.ps1 -Sign）'; return }
        & $sign -Verify
        Expect-Exit 'sign.ps1 -Verify' $LASTEXITCODE
    }
    Run-Step 'restore resident filter' {
        $exe = Join-Path $root 'FilterTool.exe'
        & $exe --lifecycle restart
        Expect-Exit '--lifecycle restart' $LASTEXITCODE
    }
}

Write-Host ''
Write-Host '=== CI summary ===' -ForegroundColor Cyan
$failed = @($script:results | Where-Object { -not $_.Ok })
foreach ($r in $script:results) {
    $tag = 'PASS'
    $color = 'Green'
    if (-not $r.Ok) { $tag = 'FAIL'; $color = 'Red' }
    Write-Host ('  [' + $tag + '] ' + $r.Name + '  ' + $r.Note) -ForegroundColor $color
}
if ($failed.Count -gt 0) {
    Write-Host ('CI FAILED: ' + $failed.Count + ' step(s)') -ForegroundColor Red
    exit 1
}
Write-Host 'CI PASSED' -ForegroundColor Green
exit 0
