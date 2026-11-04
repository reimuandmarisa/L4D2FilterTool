<#
.SYNOPSIS
    SteamServerFilter 供应链校验与构建来源证明（P2-4）。
.DESCRIPTION
    -Check       校验第三方二进制锁文件（大小 + SHA-256）、windivert 目录无未固定文件、
                 内部原生产物为 x86 PE、离线漏洞黑名单命中；失败 exit 1。
                 -Strict 时额外要求 FilterTool.exe 已签名。
    -Inventory   只打印锁文件与当前第三方组件清单，不做校验。
    -Update      重新固定第三方二进制哈希（人工确认后执行，只固定 windivert 目录）。
    -Provenance  生成构建来源证明 JSON（git 提交、构建戳、源码/产物哈希、签名信息）。
    示例：
      powershell -NoProfile -ExecutionPolicy Bypass -File tools\supply-chain.ps1 -Check
      powershell -NoProfile -ExecutionPolicy Bypass -File tools\supply-chain.ps1 -Provenance release\provenance.json -Version 20261028-1
#>
[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$Inventory,
    [switch]$Update,
    [switch]$Strict,
    [string]$Provenance = '',
    [string]$Version = ''
)
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
$root = Split-Path -Parent $PSScriptRoot
$lockPath = Join-Path $PSScriptRoot 'supply-chain.lock.json'
$advisoryPath = Join-Path $PSScriptRoot 'supply-chain.advisories.json'
$supplyDirNames = @('windivert')
$internalArtifacts = @(
    @{ path = 'FilterTool.exe'; note = '主程序（Roslyn csc + .NET Framework 4.x）' },
    @{ path = 'groupfilter\SSF_GroupFilter2.dll'; note = '注入用 x86 DLL（_work\gf2 源码构建）' }
)

function Get-Sha256([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return '' }
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Get-PeMachine([string]$path) {
    # PE COFF Machine：0x14c = x86，0x8664 = x64；不是 PE 返回 -1。
    try {
        $fs = [System.IO.File]::OpenRead($path)
        try {
            $br = New-Object System.IO.BinaryReader($fs)
            if ($br.ReadUInt16() -ne 0x5A4D) { return -1 }
            $fs.Position = 0x3C
            $peOff = $br.ReadUInt32()
            $fs.Position = $peOff
            if ($br.ReadUInt32() -ne 0x00004550) { return -1 }
            return [int]$br.ReadUInt16()
        } finally { $fs.Dispose() }
    } catch { return -1 }
}

function Get-FileVersionText([string]$path) {
    try {
        $vi = (Get-Item -LiteralPath $path).VersionInfo
        foreach ($v in @($vi.ProductVersion, $vi.FileVersion)) {
            if ($v -and ([string]$v).Trim() -ne '') { return [string]$v }
        }
    } catch { }
    return ''
}

function Get-SupplyFiles {
    $list = New-Object System.Collections.ArrayList
    foreach ($d in $supplyDirNames) {
        $dir = Join-Path $root $d
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $dir -File -Recurse)) {
            $rel = $f.FullName.Substring($root.Length + 1)
            [void]$list.Add([pscustomobject]@{
                path = $rel
                kind = 'third-party'
                size = $f.Length
                sha256 = (Get-Sha256 $f.FullName)
                version = (Get-FileVersionText $f.FullName)
            })
        }
    }
    return $list
}

function Write-Inventory([object]$items) {
    foreach ($i in $items) {
        $v = if ($i.version) { $i.version } else { '(无版本资源)' }
        Write-Host ('  ' + $i.path + '  ' + $i.size + 'B  v' + $v + '  ' + $i.sha256)
    }
}

function New-LockObject([object]$items) {
    $comps = New-Object System.Collections.ArrayList
    foreach ($i in $items) {
        [void]$comps.Add([ordered]@{
            path = $i.path
            kind = $i.kind
            version = $i.version
            size = $i.size
            sha256 = $i.sha256
        })
    }
    return [ordered]@{
        schema = 'ssf-supply-chain-lock/1'
        updatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        note = '第三方二进制按 SHA-256 固定；WinDivert 升级后必须人工执行 -Update 并复核 diff。'
        components = $comps
    }
}

function Save-Json([string]$path, [object]$obj) {
    $json = $obj | ConvertTo-Json -Depth 8
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, $json, $enc)
}

if (-not $Check -and -not $Inventory -and -not $Update -and $Provenance -eq '') {
    Write-Host '用法: tools\supply-chain.ps1 -Check | -Inventory | -Update | -Provenance <输出路径> [-Version <版本>] [-Strict]'
    exit 2
}

if ($Update) {
    $items = Get-SupplyFiles
    if ($items.Count -eq 0) { Write-Host '[FAIL] windivert 目录里没有可固定的文件'; exit 1 }
    Save-Json $lockPath (New-LockObject $items)
    Write-Host ('[OK] 已重新固定 ' + $items.Count + ' 个第三方二进制: ' + $lockPath)
    Write-Host '[WARN] 请复核 git diff 后再提交（哈希变化意味着第三方组件被替换或升级）。'
    if (-not $Check -and -not $Inventory -and $Provenance -eq '') { exit 0 }
}

if ($Inventory) {
    if (Test-Path -LiteralPath $lockPath) {
        Write-Host ('== 锁文件 ' + $lockPath + ' ==')
        $lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
        Write-Inventory $lock.components
    } else {
        Write-Host '[WARN] 锁文件不存在'
    }
    Write-Host ''
    Write-Host '== windivert 目录当前实际文件 =='
    Write-Inventory (Get-SupplyFiles)
    if (-not $Check -and $Provenance -eq '') { exit 0 }
}

if ($Check) {
    $problems = New-Object System.Collections.ArrayList
    $checks = 0
    if (-not (Test-Path -LiteralPath $lockPath)) {
        Write-Host ('[FAIL] 缺少供应链锁文件: ' + $lockPath)
        exit 1
    }
    $lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
    Write-Host ('== 第三方二进制固定校验（schema=' + $lock.schema + '，更新时间 ' + $lock.updatedAtUtc + '）==')
    $lockedPaths = @{}
    foreach ($c in $lock.components) {
        $key = ([string]$c.path).ToLowerInvariant()
        $lockedPaths[$key] = $true
        $full = Join-Path $root $c.path
        if (-not (Test-Path -LiteralPath $full)) {
            [void]$problems.Add('缺少固定组件: ' + $c.path)
            Write-Host ('  [FAIL] ' + $c.path + '  不存在')
            continue
        }
        $checks++
        $size = (Get-Item -LiteralPath $full).Length
        $sha = Get-Sha256 $full
        $okSize = ($size -eq [int64]$c.size)
        $okHash = ($sha -eq ([string]$c.sha256).ToUpperInvariant())
        if (-not $okSize) { [void]$problems.Add('大小不符: ' + $c.path + ' 期望 ' + $c.size + ' 实际 ' + $size) }
        if (-not $okHash) { [void]$problems.Add('哈希不符: ' + $c.path + ' 期望 ' + $c.sha256 + ' 实际 ' + $sha) }
        $tag = if ($okSize -and $okHash) { '[OK]  ' } else { '[FAIL]' }
        Write-Host ('  ' + $tag + ' ' + $c.path + '  ' + $size + 'B  ' + $sha)
    }
    foreach ($f in (Get-SupplyFiles)) {
        if (-not $lockedPaths.ContainsKey($f.path.ToLowerInvariant())) {
            [void]$problems.Add('windivert 目录存在未固定的第三方文件: ' + $f.path)
            Write-Host ('  [FAIL] 未固定文件: ' + $f.path)
        }
    }
    Write-Host ''
    Write-Host '== 离线依赖漏洞黑名单 =='
    if (Test-Path -LiteralPath $advisoryPath) {
        $adv = $null
        try { $adv = Get-Content -LiteralPath $advisoryPath -Raw | ConvertFrom-Json }
        catch { [void]$problems.Add('漏洞黑名单 JSON 无法解析: ' + $advisoryPath) }
        if ($adv) {
            $entries = @($adv.entries)
            $hashes = @{}
            foreach ($c in $lock.components) { $hashes[([string]$c.sha256).ToUpperInvariant()] = $c.path }
            $hits = 0
            foreach ($e in $entries) {
                if (-not $e.sha256) { continue }
                $k = ([string]$e.sha256).ToUpperInvariant()
                if ($hashes.ContainsKey($k)) {
                    $hits++
                    [void]$problems.Add('组件命中漏洞黑名单: ' + $hashes[$k] + ' <- ' + $e.id + ' [' + $e.severity + '] ' + $e.note)
                }
            }
            Write-Host ('  已登记 ' + $entries.Count + ' 条，命中 ' + $hits + ' 条')
        }
    } else {
        Write-Host '[WARN] 无 tools\supply-chain.advisories.json（只有哈希固定，没有离线漏洞黑名单）'
    }
    Write-Host ''
    Write-Host '== 内部产物（构建来源）=='
    foreach ($a in $internalArtifacts) {
        $full = Join-Path $root $a.path
        if (-not (Test-Path -LiteralPath $full)) {
            [void]$problems.Add('缺少内部产物: ' + $a.path)
            Write-Host ('  [FAIL] ' + $a.path + '  不存在')
            continue
        }
        $checks++
        $m = Get-PeMachine $full
        $size = (Get-Item -LiteralPath $full).Length
        $sha = Get-Sha256 $full
        $ok = ($m -eq 0x14C)
        if (-not $ok) { [void]$problems.Add('内部产物不是 x86 PE: ' + $a.path + ' machine=0x' + $m.ToString('X')) }
        $tag = if ($ok) { '[OK]  ' } else { '[FAIL]' }
        Write-Host ('  ' + $tag + ' ' + $a.path + '  ' + $size + 'B  machine=0x' + $m.ToString('X') + '  ' + $sha)
        Write-Host ('        ' + $a.note)
    }
    $exe = Join-Path $root 'FilterTool.exe'
    if (Test-Path -LiteralPath $exe) {
        $sig = Get-AuthenticodeSignature -FilePath $exe
        $thumb = ''
        if ($sig.SignerCertificate) { $thumb = $sig.SignerCertificate.Thumbprint }
        Write-Host ''
        $thumbText = if ($thumb) { $thumb } else { '(未签名)' }
        Write-Host ('== 主程序签名: ' + $sig.Status + '  指纹=' + $thumbText + ' ==')
        if ($Strict -and -not $thumb) { [void]$problems.Add('-Strict: FilterTool.exe 未签名') }
    }
    Write-Host ''
    if ($problems.Count -eq 0) {
        Write-Host ('[OK] 供应链校验通过（固定组件校验 ' + $checks + ' 项，无漏洞黑名单命中）')
        exit 0
    }
    Write-Host ('[FAIL] 供应链校验失败：' + $problems.Count + ' 个问题')
    foreach ($p in $problems) { Write-Host ('  - ' + $p) }
    exit 1
}

if ($Provenance -ne '') {
    if ($Version -eq '') { $Version = 'dev' }
    $exe = Join-Path $root 'FilterTool.exe'
    $buildStamp = ''
    if (Test-Path -LiteralPath $exe) {
        $out = ''
        try { $out = (& $exe --version 2>&1 | Out-String) } catch { }
        $m = [regex]::Match($out, '\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d')
        if ($m.Success) { $buildStamp = $m.Value }
        else { $buildStamp = (Get-Item -LiteralPath $exe).LastWriteTimeUtc.ToString('o') }
    }
    $gitCommit = ''
    $gitBranch = ''
    $gitDirty = $false
    try {
        $commit = (& git -C $root rev-parse HEAD 2>$null | Out-String).Trim()
        if ($LASTEXITCODE -eq 0 -and $commit) {
            $gitCommit = $commit
            $gitBranch = (& git -C $root rev-parse --abbrev-ref HEAD 2>$null | Out-String).Trim()
            $status = (& git -C $root status --porcelain 2>$null | Out-String)
            $gitDirty = ($status.Trim() -ne '')
        }
    } catch { }
    $sourceRels = New-Object System.Collections.ArrayList
    foreach ($f in (Get-ChildItem -LiteralPath (Join-Path $root '_build') -Filter '*.cs' -File)) { [void]$sourceRels.Add('_build\' + $f.Name) }
    foreach ($n in @('build.cmd', 'tests.ps1')) { if (Test-Path -LiteralPath (Join-Path $root $n)) { [void]$sourceRels.Add($n) } }
    foreach ($f in (Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File)) { [void]$sourceRels.Add('tools\' + $f.Name) }
    foreach ($n in @('_work\gf2\ssf_group_filter2.cpp', '_work\gf2\ssf_group_injector.cpp', '_work\gf2\build.cmd')) {
        if (Test-Path -LiteralPath (Join-Path $root $n)) { [void]$sourceRels.Add($n) }
    }
    $sources = New-Object System.Collections.ArrayList
    foreach ($rel in $sourceRels) { [void]$sources.Add([ordered]@{ path = $rel; sha256 = (Get-Sha256 (Join-Path $root $rel)) }) }
    $artifacts = New-Object System.Collections.ArrayList
    foreach ($rel in @('FilterTool.exe', 'groupfilter\SSF_GroupFilter2.dll')) {
        $full = Join-Path $root $rel
        if (Test-Path -LiteralPath $full) {
            [void]$artifacts.Add([ordered]@{ path = $rel; size = (Get-Item -LiteralPath $full).Length; sha256 = (Get-Sha256 $full) })
        }
    }
    $thirdParty = New-Object System.Collections.ArrayList
    if (Test-Path -LiteralPath $lockPath) {
        $lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
        foreach ($c in $lock.components) {
            [void]$thirdParty.Add([ordered]@{ path = $c.path; version = $c.version; sha256 = $c.sha256 })
        }
    }
    $sigInfo = $null
    if (Test-Path -LiteralPath $exe) {
        $s = Get-AuthenticodeSignature -FilePath $exe
        $subject = ''
        $thumb = ''
        if ($s.SignerCertificate) { $subject = $s.SignerCertificate.Subject; $thumb = $s.SignerCertificate.Thumbprint }
        $sigInfo = [ordered]@{
            status = [string]$s.Status
            signerSubject = $subject
            signerThumbprint = $thumb
        }
    }
    $prov = [ordered]@{
        schema = 'ssf-provenance/1'
        generatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        project = 'SteamServerFilter'
        version = $Version
        git = [ordered]@{ commit = $gitCommit; branch = $gitBranch; dirty = $gitDirty }
        build = [ordered]@{
            buildStamp = $buildStamp
            os = [System.Environment]::OSVersion.VersionString
            managedToolchain = 'build.cmd: Roslyn csc (.NET Framework 4.x) -> FilterTool.exe'
            nativeToolchain = 'MSVC v14.3 x86 via _work\gf2\build.cmd -> SSF_GroupFilter2.dll'
        }
        sources = @($sources)
        artifacts = @($artifacts)
        thirdParty = @($thirdParty)
        sbom = 'sbom.json'
        signature = $sigInfo
        notes = '由 tools\supply-chain.ps1 -Provenance 生成，用作构建来源证明；GitHub Actions 尚未实跑。'
    }
    $parent = Split-Path -Parent $Provenance
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    Save-Json $Provenance $prov
    $commitText = if ($gitCommit) { $gitCommit } else { '(非 git 或不可用)' }
    Write-Host ('[OK] 已生成构建来源证明: ' + $Provenance)
    Write-Host ('     git=' + $commitText + ' dirty=' + $gitDirty + ' sources=' + $sources.Count + ' artifacts=' + $artifacts.Count)
    exit 0
}
