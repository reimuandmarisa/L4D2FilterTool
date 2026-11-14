<#
.SYNOPSIS
    SteamServerFilter 发布前置检查与打包（P2）。
.DESCRIPTION
    -Check    扫描工作区里不应发布的运行时敏感数据（日志/抓包/名字-IP 映射/语料/证据），
              并列出发布包将包含的白名单文件。-Strict 时有敏感文件即返回 1。
    -Package  生成 release\SteamServerFilter-<ver>.zip、SHA256SUMS.txt、sbom.json。
              默认要求 -Sign 且签名证书指纹必须等于 -ExpectedThumbprint；未签名即失败（exit 2）。
              本地调试如确需未签名包，必须显式加 -AllowUnsigned。
    示例：
      powershell -NoProfile -ExecutionPolicy Bypass -File tools\release.ps1 -Check
      powershell -NoProfile -ExecutionPolicy Bypass -File tools\release.ps1 -Check -Strict
      powershell -NoProfile -ExecutionPolicy Bypass -File tools\release.ps1 -Package
#>
[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$Package,
    [switch]$Strict,
    [switch]$Sign,
    [switch]$VerifySignature,
    [switch]$AllowUnsigned,
    [string]$CertThumbprint = '',
    [string]$ExpectedThumbprint = '2917D295E886F1051C42F971CAD9F7FA68559F81',
    [string]$PfxPath = '',
    [string]$PfxPassword = '',
    [string]$OutDir = '',
    [string]$Version = ''
)
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
$root = Split-Path -Parent $PSScriptRoot
if (-not $Check -and -not $Package) { $Check = $true }

$sensitiveGlobs = @(
    'Logs\*',
    '*.log',
    'name_ip_map.tsv',
    'name_ip_map.tsv*',
    'name_layer_seen.tsv*',
    'name_layer_blocked.txt',
    'pending_resolve.tsv',
    'ip_block.txt',
    'block_rules.backup*.txt',
    'steam_aliases.tsv',
    'name_ip_links.tsv',
    'ip_block.heartbeat.txt',
    '*_compare.json',
    'cmp*.tsv',
    '*~RF*.TMP',
    '_work\\evidence\\*',
    '_archive\\legacy-binaries\\*',
    '_work\corpus_*.tsv',
    '_work\*\evidence\*',
    '_work\*\*.json',
    'dumps\*',
    'tools\certs\*.pfx'
)

function Get-RelPath([string]$full) {
    return $full.Substring($root.Length + 1)
}

function Test-SensitiveRel([string]$rel) {
    foreach ($g in $sensitiveGlobs) {
        if ($rel -like $g) { return $true }
    }
    return $false
}

function Find-Sensitive {
    $result = New-Object System.Collections.ArrayList
    foreach ($f in (Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue)) {
        $rel = Get-RelPath $f.FullName
        if (Test-SensitiveRel $rel) { [void]$result.Add($rel) }
    }
    return $result
}

$packageFiles = @(
    'FilterTool.exe',
    'RulesTool.cmd',
    'RulesTool.ps1',
    'build.cmd',
    'tests.ps1',
    'README.md',
    'LICENSE'
)
$packageDirs = @('windivert', 'rules-profiles')

function Get-PackageList {
    $list = New-Object System.Collections.ArrayList
    foreach ($f in $packageFiles) {
        if (Test-Path -LiteralPath (Join-Path $root $f)) { [void]$list.Add($f) }
        else { Write-Warning ('缺少发布文件: ' + $f) }
    }
    foreach ($d in $packageDirs) {
        $p = Join-Path $root $d
        if (-not (Test-Path -LiteralPath $p)) { Write-Warning ('缺少发布目录: ' + $d); continue }
        foreach ($f in (Get-ChildItem -LiteralPath $p -Recurse -File)) {
            $rel = Get-RelPath $f.FullName
            if ($rel -like 'rules-profiles\.backup\*') { continue }
            # 个性化 custom.txt 不进发布包（可能含用户自己的屏蔽名单），打包时写干净模板。
            if ($rel -eq 'rules-profiles\custom.txt') { continue }
            [void]$list.Add($rel)
        }
    }
    return $list
}

function Get-Sha256([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return '' }
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Get-PackageConflicts([object]$pkg) {
    $bad = New-Object System.Collections.ArrayList
    foreach ($rel in $pkg) { if (Test-SensitiveRel $rel) { [void]$bad.Add($rel) } }
    return $bad
}

# Get-PackageList 返回枚举结果（固定大小数组）；打包阶段还要追加生成的 custom 模板，
# 所以这里转成可增删的 ArrayList。
$pkg = [System.Collections.ArrayList]@(Get-PackageList)
$conflicts = Get-PackageConflicts $pkg

if ($Check) {
    Write-Host '== 发布前敏感数据扫描 =='
    $dirty = Find-Sensitive
    if ($dirty.Count -eq 0) {
        Write-Host '[OK] 工作区没有发现运行时敏感数据'
    } else {
        Write-Host ('[WARN] 发现 ' + $dirty.Count + ' 个运行时敏感文件（不应提交/发布）:')
        foreach ($b in ($dirty | Sort-Object | Select-Object -First 50)) { Write-Host ('  ' + $b) }
        if ($dirty.Count -gt 50) { Write-Host ('  ...（共 ' + $dirty.Count + ' 个）') }
    }
    Write-Host ''
    Write-Host '== 发布包白名单 =='
    foreach ($p in $pkg) { Write-Host ('  ' + $p) }
    if ($conflicts.Count -gt 0) {
        Write-Host ''
        Write-Host '[FAIL] 发布包清单里含敏感文件，已阻止发布:'
        foreach ($c in $conflicts) { Write-Host ('  ' + $c) }
        exit 1
    }
    Write-Host '[OK] 发布包清单检查通过（只打包上面这些文件）'
    Write-Host ''
    Write-Host '== Authenticode 签名状态 =='
    $exePath = Join-Path $root 'FilterTool.exe'
    if (Test-Path -LiteralPath $exePath) {
        $sigInfo = Get-AuthenticodeSignature -FilePath $exePath
        Write-Host ('  FilterTool.exe: ' + $sigInfo.Status + '  ' + $sigInfo.StatusMessage)
        if ($sigInfo.SignerCertificate) {
            Write-Host ('  签名者: ' + $sigInfo.SignerCertificate.Subject + '  指纹=' + $sigInfo.SignerCertificate.Thumbprint)
        } else {
            Write-Host '  [WARN] 未签名（发布前建议 tools\sign.ps1 -Sign）'
        }
        if ($VerifySignature) {
            $signScript = Join-Path $PSScriptRoot 'sign.ps1'
            & powershell -NoProfile -ExecutionPolicy Bypass -File $signScript -Verify -FilePath $exePath -Thumbprint $CertThumbprint
            if ($LASTEXITCODE -ne 0) { Write-Host '[FAIL] -VerifySignature：签名校验失败'; exit 1 }
            Write-Host '  [OK] -VerifySignature 通过'
        }
    } else {
        Write-Host '  [WARN] FilterTool.exe 不存在'
    }
    Write-Host ''
    Write-Host '== 供应链固定与依赖漏洞扫描 =='
    $supplyScript = Join-Path $PSScriptRoot 'supply-chain.ps1'
    if (Test-Path -LiteralPath $supplyScript) {
        & powershell -NoProfile -ExecutionPolicy Bypass -File $supplyScript -Check
        if ($LASTEXITCODE -ne 0) { Write-Host '[FAIL] supply-chain.ps1 -Check 未通过'; exit 1 }
    } else {
        Write-Host '[WARN] 缺少 tools\supply-chain.ps1，跳过供应链校验'
    }
    if ($Strict -and $dirty.Count -gt 0) { Write-Host '[FAIL] -Strict：工作区仍有敏感文件，请先清理'; exit 1 }
    if (-not $Package) { exit 0 }
}

if ($Package) {
    if ($conflicts.Count -gt 0) { Write-Host '[FAIL] 发布包清单里含敏感文件，已阻止打包'; exit 1 }
    $expectedThumb = if ($CertThumbprint -ne '') { $CertThumbprint } else { $ExpectedThumbprint }
    if (-not $AllowUnsigned -and -not $Sign) {
        Write-Host '[FAIL] -Package 要求同时使用 -Sign（发布包必须签名，见 tools/sign.ps1）；'
        Write-Host '       本地调试如确需未签名包，必须显式加 -AllowUnsigned。'
        exit 2
    }
    if ($OutDir -eq '') { $OutDir = Join-Path $root 'release' }
    if ($Version -eq '') {
        $exe = Join-Path $root 'FilterTool.exe'
        if (Test-Path -LiteralPath $exe) { $Version = (Get-Item -LiteralPath $exe).LastWriteTime.ToString('yyyyMMdd-HHmm') }
        else { $Version = 'dev' }
    }
    if ($Sign) {
        Write-Host ''
        Write-Host '== 签名 FilterTool.exe =='
        $signScript = Join-Path $PSScriptRoot 'sign.ps1'
        & powershell -NoProfile -ExecutionPolicy Bypass -File $signScript -Sign -FilePath (Join-Path $root 'FilterTool.exe') -Thumbprint $CertThumbprint -PfxPath $PfxPath -PfxPassword $PfxPassword
        if ($LASTEXITCODE -ne 0) { Write-Host '[FAIL] 签名失败，已阻止打包'; exit 1 }
    }
    if (-not $AllowUnsigned) {
        $signScript = Join-Path $PSScriptRoot 'sign.ps1'
        & powershell -NoProfile -ExecutionPolicy Bypass -File $signScript -Verify -FilePath (Join-Path $root 'FilterTool.exe') -Thumbprint $expectedThumb
        if ($LASTEXITCODE -ne 0) {
            Write-Host ('[FAIL] FilterTool.exe 签名无效或证书指纹不是 ' + $expectedThumb + '，已阻止打包')
            exit 2
        }
        Write-Host ('[OK] FilterTool.exe 签名有效，证书指纹=' + $expectedThumb)
    } else {
        Write-Host '[WARN] -AllowUnsigned：本次发布包未签名，仅限本地调试，禁止对外分发。'
    }

    $stage = Join-Path $OutDir ('stage-' + $Version)
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    foreach ($rel in $pkg) {
        $dst = Join-Path $stage $rel
        $dir = Split-Path -Parent $dst
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Copy-Item -LiteralPath (Join-Path $root $rel) -Destination $dst -Force
    }
    # P0-5：发布包只带干净的 custom 模板，绝不带上用户本机的个性化名单。
    $customRel = 'rules-profiles\custom.txt'
    $customPath = Join-Path $stage $customRel
    $customDir = Split-Path -Parent $customPath
    if (-not (Test-Path -LiteralPath $customDir)) { New-Item -ItemType Directory -Path $customDir -Force | Out-Null }
    $customTemplate = @(
        '# ============================================================'
        '# 规则档 custom —— 发布包内的干净模板（不含任何个人规则）'
        '# ============================================================'
        '# 这里是你一条条加进来的精确规则（只匹配指定的服务器名）。'
        '# 也可以直接编辑本文件（支持 # 注释），改完在工具里点「重新生成并重启」。'
        '# ============================================================'
    )
    Set-Content -LiteralPath $customPath -Value $customTemplate -Encoding UTF8
    [void]$pkg.Add($customRel)
    # P2-4：生成构建来源证明（provenance.json），随包发布并进入 SHA256SUMS 与 sbom。
    $supplyScript = Join-Path $PSScriptRoot 'supply-chain.ps1'
    if (Test-Path -LiteralPath $supplyScript) {
        $provPath = Join-Path $stage 'provenance.json'
        & powershell -NoProfile -ExecutionPolicy Bypass -File $supplyScript -Provenance $provPath -Version $Version
        if ($LASTEXITCODE -ne 0) { Write-Host '[FAIL] 生成构建来源证明失败，已阻止打包'; exit 1 }
        [void]$pkg.Add('provenance.json')
        Write-Host ('[OK] 构建来源证明: ' + $provPath)
    } else {
        Write-Host '[WARN] 缺少 tools\supply-chain.ps1，发布包不含 provenance.json'
    }
    $sums = New-Object System.Collections.ArrayList
    foreach ($rel in $pkg) { [void]$sums.Add((Get-Sha256 (Join-Path $stage $rel)) + '  ' + $rel) }
    $nl = [Environment]::NewLine
    Set-Content -LiteralPath (Join-Path $stage 'SHA256SUMS.txt') -Value ($sums -join $nl) -Encoding ASCII

    if ($VerifySignature) {
        $stagedExe = Join-Path $stage 'FilterTool.exe'
        $signScript = Join-Path $PSScriptRoot 'sign.ps1'
        & powershell -NoProfile -ExecutionPolicy Bypass -File $signScript -Verify -FilePath $stagedExe -Thumbprint $expectedThumb
        if ($LASTEXITCODE -ne 0) { Write-Host '[FAIL] -VerifySignature：发布包内 FilterTool.exe 签名校验失败'; exit 1 }
        Write-Host '[OK] 发布包内 FilterTool.exe 签名校验通过'
    }

    $components = New-Object System.Collections.ArrayList
    foreach ($rel in $pkg) {
        [void]$components.Add([ordered]@{
            type = 'file'
            name = $rel
            hashes = @(@{ alg = 'SHA-256'; content = (Get-Sha256 (Join-Path $stage $rel)) })
        })
    }
    $dllNative = Join-Path $root '_work\gf2\dist\SSF_GroupFilter2.dll'
    if (Test-Path -LiteralPath $dllNative) {
        [void]$components.Add([ordered]@{
            type = 'library'
            name = 'SSF_GroupFilter2.dll (embedded in FilterTool.exe)'
            version = 'safe-nfa-1'
            hashes = @(@{ alg = 'SHA-256'; content = (Get-Sha256 $dllNative) })
        })
    }
    $wd = Join-Path $root 'windivert\WinDivert.dll'
    if (Test-Path -LiteralPath $wd) {
        [void]$components.Add([ordered]@{
            type = 'library'
            name = 'WinDivert.dll (pinned path + SHA-256)'
            version = 'pinned'
            hashes = @(@{ alg = 'SHA-256'; content = (Get-Sha256 $wd) })
        })
    }
    $sbom = [ordered]@{
        bomFormat = 'CycloneDX-lite'
        specVersion = '1.4'
        version = 1
        metadata = [ordered]@{
            timestamp = (Get-Date).ToString('o')
            component = [ordered]@{ type = 'application'; name = 'SteamServerFilter'; version = $Version }
        }
        components = $components
    }
    $stagedExeForSbom = Join-Path $stage 'FilterTool.exe'
    if (Test-Path -LiteralPath $stagedExeForSbom) {
        $sigSbom = Get-AuthenticodeSignature -FilePath $stagedExeForSbom
        $sbom.metadata['authenticode'] = [ordered]@{
            status = [string]$sigSbom.Status
            signerSubject = if ($sigSbom.SignerCertificate) { $sigSbom.SignerCertificate.Subject } else { '' }
            signerThumbprint = if ($sigSbom.SignerCertificate) { $sigSbom.SignerCertificate.Thumbprint } else { '' }
            expectedThumbprint = $expectedThumb
            requirement = if ($AllowUnsigned) { 'unsigned-allowed-local-debug' } else { 'signed-required' }
        }
    }

    $sbom.metadata['supplyChain'] = [ordered]@{
        lock = 'tools/supply-chain.lock.json'
        advisories = 'tools/supply-chain.advisories.json'
        provenance = 'provenance.json'
        dependencyScan = 'offline hash pinning + advisories blocklist (no live CVE database)'
    }
    $sbom | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $stage 'sbom.json') -Encoding UTF8

    $zip = Join-Path $OutDir ('SteamServerFilter-' + $Version + '.zip')
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force
    Copy-Item -LiteralPath (Join-Path $stage 'SHA256SUMS.txt') -Destination (Join-Path $OutDir 'SHA256SUMS.txt') -Force
    Write-Host ('[OK] 发布包: ' + $zip)
    Write-Host ('[OK] 发布包 SHA-256: ' + (Get-Sha256 $zip))
    Write-Host ('[OK] 清单: ' + (Join-Path $OutDir 'SHA256SUMS.txt') + ' / ' + (Join-Path $stage 'sbom.json'))
}
