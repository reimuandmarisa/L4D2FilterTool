<#
.SYNOPSIS
    检查/加固 SteamServerFilter 可执行文件与原生 DLL 目录的 Windows 文件 ACL。

.DESCRIPTION
    默认只检查（-Check 行为），加 -Apply 才真正收紧。
    目标：windivert\、groupfilter\、rules-profiles\、tools\certs\ 及其文件，FilterTool.exe、
          config.ini、规则与状态文件的可写权限只保留
          NT AUTHORITY\SYSTEM / BUILTIN\Administrators / 当前用户，
          去掉 CodexSandboxUsers、未知 SID 等继承来的可写 ACE
          （这类 ACE 让非管理员进程也能替换 FilterTool.exe 或原生 DLL，属于提权面）。
    注意：目录与目录内每个文件都单独处理（目录带 (OI)(CI)，文件不带），
          这样不会把文件 ACL 清空。

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\harden-acl.ps1
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\harden-acl.ps1 -Apply
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\harden-acl.ps1 -Check -Strict
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Check,
    [switch]$Strict
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }

$Root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = (Get-Location).Path }

# 目录目标：递归处理目录本身与其下每个文件/子目录（不使用 icacls /T，避免清空子文件 DACL）。
$treeTargets = @(
    'windivert',
    'groupfilter',
    'rules-profiles',
    'tools\certs'
)

# 文件目标：可执行文件、配置文件、规则/状态文件（非管理员改写这些文件会影响拦截行为）。
$fileTargets = @(
    'FilterTool.exe',
    'config.ini',
    'block_rules.txt',
    'block_mode.txt',
    'group_filter_rules.txt',
    'name_layer.txt',
    'log_retention.txt',
    'tray.txt',
    'pending_resolve.tsv'
)

$targets = @()
foreach ($rel in $treeTargets) { $targets += (Join-Path $Root $rel) }
foreach ($rel in $fileTargets) { $targets += (Join-Path $Root $rel) }

# 注意：不把项目根目录本身作为目标——在根上设置可继承 ACE 会被系统向整棵工作区传播，
# 可能与 _build/_work/_archive 的既有 ACL 冲突；可执行文件、原生 DLL、规则档与状态文件已逐一覆盖。

$user = if ($env:USERDOMAIN) { $env:USERDOMAIN + '\' + $env:USERNAME } else { $env:USERNAME }
$allowed = @(
    'NT AUTHORITY\SYSTEM',
    'BUILTIN\Administrators',
    $user
)

$writePattern = 'Write|Modify|FullControl|CreateFiles|CreateDirectories|AppendData|Delete'

function Get-AclEntries {
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $out = @()
    foreach ($ace in @($acl.Access)) {
        if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        $identity = $ace.IdentityReference
        $principal = $identity.Value
        if ([string]::IsNullOrWhiteSpace($principal)) { $principal = [string]$identity }
        $rightsText = $ace.FileSystemRights.ToString()
        $writable = [bool]($rightsText -match $writePattern)
        $allowedHere = $false
        foreach ($a in $allowed) {
            if ([string]::Equals($a, $principal, [System.StringComparison]::OrdinalIgnoreCase)) { $allowedHere = $true; break }
        }
        $out += [pscustomobject]@{
            Path      = $Path
            Principal = $principal
            Rights    = $rightsText
            Inherited = $ace.IsInherited
            Writable  = $writable
            Allowed   = $allowedHere
        }
    }
    return $out
}

function Get-TargetObjects {
    param([string]$Path)
    $objs = @()
    if (-not (Test-Path -LiteralPath $Path)) { return $objs }
    $objs += (Get-Item -LiteralPath $Path)
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        $objs += @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue)
    }
    return $objs
}

function Show-Target {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host ('  [跳过] ' + $Path + ' 不存在') -ForegroundColor DarkGray
        return @()
    }
    $bad = @()
    foreach ($obj in (Get-TargetObjects -Path $Path)) {
        $entries = @(Get-AclEntries -Path $obj.FullName)
        $objBad = @($entries | Where-Object { $_.Writable -and -not $_.Allowed })
        $rel = $obj.FullName.Substring($Root.Length + 1)
        if ($entries.Count -eq 0) {
            Write-Host ('    ' + $rel + '  -> [FAIL] 没有任何 ACE（DACL 为空，等于谁都访问不了）') -ForegroundColor Red
            $bad += [pscustomobject]@{ Path = $obj.FullName; Principal = '(empty dacl)'; Rights = ''; Inherited = $false; Writable = $true; Allowed = $false }
            continue
        }
        foreach ($e in $entries) {
            $isBad = $e.Writable -and -not $e.Allowed
            $color = if ($isBad) { 'Yellow' } else { 'DarkGray' }
            $inherited = if ($e.Inherited) { '(继承)' } else { '(显式)' }
            Write-Host ('    ' + $rel + '  ' + $e.Principal + '  ' + $e.Rights + '  ' + $inherited) -ForegroundColor $color
        }
        if ($objBad.Count -gt 0) { $bad += $objBad }
    }
    if ($bad.Count -eq 0) {
        Write-Host '    结论: OK（没有非白名单写权限，且 DACL 完整）' -ForegroundColor Green
    } else {
        Write-Host ('    结论: 发现 ' + $bad.Count + ' 个非白名单/异常 ACE，建议 -Apply') -ForegroundColor Yellow
    }
    return $bad
}

function Get-GrantList([bool]$isDir) {
    if ($isDir) {
        return @(
            ($sys + ':(OI)(CI)F'),
            ($adm + ':(OI)(CI)F'),
            ($user + ':(OI)(CI)F')
        )
    }
    return @(
        ($sys + ':F'),
        ($adm + ':F'),
        ($user + ':F')
    )
}

function Apply-Object([string]$path, [bool]$isDir) {
    $grant = Get-GrantList $isDir
    $out = & icacls $path /inheritance:r /grant:r @grant /C /Q 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Write-Host ('      [FAIL] icacls exit=' + $code + '  ' + $path) -ForegroundColor Red
        foreach ($line in @($out)) {
            $text = ([string]$line).Trim()
            if ($text) { Write-Host ('        ' + $text) -ForegroundColor Red }
        }
        return $false
    }
    return $true
}

function Invoke-Harden {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    $ok = $true
    foreach ($obj in (Get-TargetObjects -Path $Path)) {
        $isDir = $obj.PSIsContainer
        if (-not (Apply-Object -path $obj.FullName -isDir $isDir)) { $ok = $false }
    }
    return $ok
}

$sys = 'NT AUTHORITY\SYSTEM'
$adm = 'BUILTIN\Administrators'

Write-Host '=== SteamServerFilter 文件 ACL 检查 ==='
Write-Host ('项目根: ' + $Root)
Write-Host ('允许的可写主体: ' + ($allowed -join '、'))
Write-Host ''

$allBad = @()
foreach ($t in $targets) {
    Write-Host ('[' + $t + ']')
    $bad = @(Show-Target -Path $t)
    $allBad += $bad
}

if ($Apply) {
    Write-Host ''
    Write-Host '=== 收紧 ACL（-Apply） ==='
    $okAll = $true
    foreach ($t in $targets) {
        if (-not (Test-Path -LiteralPath $t)) { continue }
        Write-Host ('[' + $t + ']')
        if (-not (Invoke-Harden -Path $t)) { $okAll = $false }
    }
    Write-Host ''
    Write-Host '=== 收紧后复查 ==='
    $after = @()
    foreach ($t in $targets) {
        if (-not (Test-Path -LiteralPath $t)) { continue }
        $after += @(Show-Target -Path $t)
    }
    Write-Host ''
    if ($after.Count -eq 0) {
        Write-Host 'ACL 加固结果: OK（0 个非白名单/异常 ACE）' -ForegroundColor Green
    } else {
        Write-Host ('ACL 加固结果: 仍有 ' + $after.Count + ' 个非白名单/异常 ACE') -ForegroundColor Red
        $okAll = $false
    }
    if (-not $okAll) { exit 2 }
    exit 0
}

if ($allBad.Count -gt 0) {
    Write-Host ''
    Write-Host ('共 ' + $allBad.Count + ' 个非白名单/异常 ACE。加 -Apply 收紧（需要管理员权限）：') -ForegroundColor Yellow
    Write-Host '  powershell -NoProfile -ExecutionPolicy Bypass -File tools\harden-acl.ps1 -Apply'
    if ($Strict) { exit 1 }
}
exit 0
