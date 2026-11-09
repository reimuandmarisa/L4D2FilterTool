<#
.SYNOPSIS
    SteamServerFilter 规则工具：精确模拟规则引擎 + 统一规则文件管理 + 校验 + 重启。

.DESCRIPTION
    SteamServerFilter(.NET 6 单文件) 的规则引擎实际行为（已逆向确认）：
      1. 以 UTF-8 读取 block_rules.txt（不是 ANSI/GBK！）
      2. 逐行 split，跳过空行/纯空白行
      3. 对完全相同的行做去重（序数比较，区分大小写），只保留一条
      4. 每行编译成 .NET Regex（无 IgnoreCase、无锚定）
      5. 对 A2S 查到的服务器名做 Regex.IsMatch —— 名字里任意位置命中即拉黑该 endpoint
      6. 日志打印 "N rules have been read."，N = 去重后的条数

    本脚本用同一个 .NET Regex 引擎来模拟上述过程，所以检查结果与程序一致；
    并能一眼看出「文件存成 GBK 导致规则变乱码」这类静默失效问题。

.EXAMPLE
    RulesTool.cmd status
    RulesTool.cmd check
    RulesTool.cmd test
    RulesTool.cmd apply rpg+cn
    RulesTool.cmd restart
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Command = 'status',
    [Parameter(Position = 1)][string]$Arg = '',
    [Parameter(Position = 2, ValueFromRemainingArguments = $true)][string[]]$Rest = @()
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }

$Root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$RulesFile = Join-Path $Root 'block_rules.txt'
$ProfileDir= Join-Path $Root 'rules-profiles'
$LogDir    = Join-Path $Root 'Logs'
$TaskName  = 'SteamServerFilter IP Block'
$ExeName   = 'FilterTool.exe'
$CustomProfile = Join-Path $ProfileDir 'custom.txt'     # add 命令写入的"自定义规则"
$StateFile     = Join-Path $ProfileDir '.active-profile' # 记住当前启用的规则档组合
$BackupDir     = Join-Path $ProfileDir '.backup'         # 引擎生成的备份（--rules-backup / --rules-apply）

$UTF8NoBom    = New-Object System.Text.UTF8Encoding($false)
$UTF8Strict   = New-Object System.Text.UTF8Encoding($false, $true)
$Ordinal      = [System.StringComparer]::Ordinal

# ---------------------------------------------------------------- helpers
function Write-Title([string]$t) { Write-Host ''; Write-Host ("== " + $t + " ==") -ForegroundColor Cyan }
function Write-Ok  ([string]$t) { Write-Host ("  [OK]   " + $t) -ForegroundColor Green }
function Write-Warn2([string]$t){ Write-Host ("  [警告] " + $t) -ForegroundColor Yellow }
function Write-Bad ([string]$t) { Write-Host ("  [错误] " + $t) -ForegroundColor Red }
function Write-Info([string]$t) { Write-Host ("         " + $t) -ForegroundColor Gray }

# 程序运行时会占用当天的日志文件，必须用共享读
function Read-TextShared {
    param([string]$Path)
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
        try { return $sr.ReadToEnd() } finally { $sr.Dispose() }
    } finally { $fs.Dispose() }
}

function Get-OrdinalDistinct {
    param([string[]]$Items)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' $Ordinal
    $out  = New-Object System.Collections.Generic.List[string]
    foreach ($i in $Items) { if ($seen.Add($i)) { $out.Add($i) } }
    return $out.ToArray()
}

# 模拟引擎：把文件解析成「生效规则」
# 单个字符是否"不像正常服名里会出现的东西"——乱码的典型特征。
# 注意：GBK 被当 UTF-8 读时，有些字节对恰好是合法 UTF-8 序列，
# 会变成希腊字母/拉丁扩展字母等（例如 趣 -> Ȥ、味 -> ζ），这类规则永远匹配不到真实服名。
function Test-CharLooksMangled {
    param([char]$c)
    $v = [int]$c
    if ($v -lt 0x80)        { return $false }                 # ASCII
    if ($v -ge 0x2000 -and $v -le 0x2BFF) { return $false }   # 符号 / 标点（★☆♂♀①❶※ 等）
    if ($v -ge 0x3000 -and $v -le 0x30FF) { return $false }   # CJK 标点（、【】「」）+ 日文假名（の）
    if ($v -ge 0x3400 -and $v -le 0x4DBF) { return $false }   # CJK 扩展 A
    if ($v -ge 0x4E00 -and $v -le 0x9FFF) { return $false }   # CJK 汉字
    if ($v -ge 0xAC00 -and $v -le 0xD7AF) { return $false }   # 谚文
    if ($v -ge 0xD800 -and $v -le 0xDFFF) { return $false }   # 代理对（emoji）
    if ($v -ge 0xF900 -and $v -le 0xFAFF) { return $false }   # CJK 兼容汉字
    if ($v -ge 0xFE30 -and $v -le 0xFE4F) { return $false }
    if ($v -ge 0xFF00 -and $v -le 0xFFEF) { return $false }   # 全角 / 半角形式
    if ($v -ge 0x1F300 -and $v -le 0x1FAFF) { return $false } # emoji
    return $true
}

function Read-EngineRuleSet {
    param([string]$Path)

    $result = [pscustomobject]@{
        Path            = $Path
        Exists          = $false
        ByteLength      = 0
        HasBom          = $false
        IsValidUtf8     = $false
        PhysicalLines   = 0
        NonBlankLines   = 0
        EffectiveRules  = @()
        Duplicates      = @()
        MangledRules    = @()   # 含 U+FFFD，永远匹配不到真实服务器名 -> 死规则
        SuspiciousRules = @()   # 含"不该出现"的非中文字符（乱码变体的典型特征）
        InvalidRegex    = @()
        WhiteSpaceRules = @()
    }
    if (-not (Test-Path -LiteralPath $Path)) { return $result }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $result.Exists     = $true
    $result.ByteLength = $bytes.Length

    $result.HasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)

    try { [void]$UTF8Strict.GetString($bytes); $result.IsValidUtf8 = $true } catch { $result.IsValidUtf8 = $false }

    # 与引擎一致：按 UTF-8 解码（非法字节 -> U+FFFD），再去 BOM
    $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }

    $lines = @($text -split "`r`n|`n|`r")
    # 末尾换行会产生一个多余的空串，不算作物理行
    $result.PhysicalLines = if ($text.EndsWith("`n") -or $text.EndsWith("`r")) { $lines.Count - 1 } else { $lines.Count }

    $nonBlank = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $result.NonBlankLines = $nonBlank.Count

    $dups = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' $Ordinal
    $rules = New-Object System.Collections.Generic.List[string]
    foreach ($l in $nonBlank) {
        if (-not $seen.Add($l)) { $dups.Add($l) } else { $rules.Add($l) }
    }
    $result.Duplicates     = $dups.ToArray()
    $result.EffectiveRules = $rules.ToArray()

    $mangled = New-Object System.Collections.Generic.List[string]
    $susp    = New-Object System.Collections.Generic.List[string]
    $invalid = New-Object System.Collections.Generic.List[string]
    $ws      = New-Object System.Collections.Generic.List[string]
    foreach ($r in $result.EffectiveRules) {
        if ($r.IndexOf([char]0xFFFD) -ge 0) { $mangled.Add($r) }
        foreach ($ch in $r.ToCharArray()) {
            if (Test-CharLooksMangled $ch) { $susp.Add($r); break }
        }
        if ($r -ne $r.Trim()) { $ws.Add($r) }
        try { [void](New-Object System.Text.RegularExpressions.Regex($r)) }
        catch { $invalid.Add(("{0}   <- {1}" -f $r, $_.Exception.Message)) }
    }
    $result.MangledRules    = $mangled.ToArray()
    $result.SuspiciousRules = $susp.ToArray()
    $result.InvalidRegex    = $invalid.ToArray()
    $result.WhiteSpaceRules = $ws.ToArray()
    return $result
}

# 读取一个规则档（支持 a+b 组合）；剥掉 '#' 注释与空行，序数去重
function Get-ProfileRules {
    param([string]$Name)
    $parts = $Name -split '\+'
    $all   = New-Object System.Collections.Generic.List[string]
    foreach ($p in $parts) {
        $p = $p.Trim()
        if ($p -eq '') { continue }
        $f = Join-Path $ProfileDir ($p + '.txt')
        if (-not (Test-Path -LiteralPath $f)) { throw ("找不到规则档: " + $f) }
        $lines = [System.IO.File]::ReadAllLines($f, $UTF8NoBom)
        foreach ($l in $lines) {
            if ([string]::IsNullOrWhiteSpace($l)) { continue }
            if ($l.TrimStart().StartsWith('#')) { continue }
            $all.Add($l.Trim())
        }
    }
    return (Get-OrdinalDistinct $all.ToArray())
}

# 写出「引擎安全」的 block_rules.txt：UTF-8 无 BOM、无注释、无空行、无重复、CRLF
# 记住 / 读取当前启用的规则档组合（例如 "rpg" 或 "rpg+custom"）
function Get-ActiveProfile {
    if (Test-Path -LiteralPath $StateFile) {
        $v = ([System.IO.File]::ReadAllText($StateFile, $UTF8NoBom)).Trim()
        if ($v -ne '') { return $v }
    }
    return 'rpg'
}
function Set-ActiveProfile {
    param([string]$Name)
    [System.IO.File]::WriteAllText($StateFile, $Name.Trim(), $UTF8NoBom)
}

# 把服务器名转成一条"精确"或"数字通配"的正则
function New-RuleFromName {
    param([string]$Name, [switch]$Loose)
    $exact = [System.Text.RegularExpressions.Regex]::Escape($Name.Trim())
    if (-not $Loose) { return $exact }
    # 数字段变成 \d+，这样同族服的编号变化也能一并盖住
    return [System.Text.RegularExpressions.Regex]::Replace($exact, '\d+', '\d+')
}

function Write-RulesFile {
    param([string[]]$Rules, [string]$Path)
    $clean = Get-OrdinalDistinct (@($Rules | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }))
    $text  = ($clean -join "`r`n") + "`r`n"
    [System.IO.File]::WriteAllText($Path, $text, $UTF8NoBom)
    return $clean
}

function Backup-Rules {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $stamp = (Get-Item -LiteralPath $Path).LastWriteTime.ToString('yyyyMMdd-HHmmss')
    $bak   = ("{0}.{1}.bak" -f $Path, $stamp)
    Copy-Item -LiteralPath $Path -Destination $bak -Force
    return $bak
}

# 从 Logs 里挖出历史上被拦过的服务器名（语料）
function Get-Corpus {
    $names = @{}
    if (-not (Test-Path -LiteralPath $LogDir)) { return @() }
    $rxName = [System.Text.RegularExpressions.Regex]'Block server with name: (.*)$'
    foreach ($f in Get-ChildItem -LiteralPath $LogDir -Filter *.log) {
        $txt = Read-TextShared $f.FullName
        foreach ($line in ($txt -split "`r`n|`n|`r")) {
            $m = $rxName.Match($line)
            if ($m.Success) {
                $n = $m.Groups[1].Value
                if ($names.ContainsKey($n)) { $names[$n]++ } else { $names[$n] = 1 }
            }
        }
    }
    return @($names.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
        [pscustomobject]@{ Count = [int]$_.Value; Name = [string]$_.Key }
    })
}

function Get-RuleHits {
    param([string[]]$Rules, [object[]]$Corpus)
    # V-16: 引擎对规则做序数（区分大小写）去重，这里也用序数键——
    #       PowerShell 的 @{} 大小写不敏感，仅大小写不同的两条规则会互相覆盖命中数
    $map = New-Object 'System.Collections.Generic.Dictionary[string,int]' (, $Ordinal)
    foreach ($r in $Rules) {
        try {
            $rx = New-Object System.Text.RegularExpressions.Regex($r)
            $sum = 0
            foreach ($c in $Corpus) { if ($rx.IsMatch($c.Name)) { $sum += $c.Count } }
            $map[$r] = $sum
        } catch { $map[$r] = -1 }
    }
    return $map
}

# ---------------------------------------------------------------- commands
# 规则集的"唯一解析"来自引擎：FilterTool.exe --rules（SteamServerFilterRules 引擎按真实读取逻辑
# 解析 block_rules.txt）。check 时用它做一致性交叉核对，避免 PowerShell 另写一套解析后悄悄漂移。
function Get-EngineRulesViaCli {
    $exe = Join-Path $Root $ExeName
    if (-not (Test-Path -LiteralPath $exe)) { return $null }
    try {
        $out  = & $exe --rules 2>&1 | Out-String
        $code = $LASTEXITCODE
    } catch { return $null }
    if ($code -ne 0) { return $null }
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($line in ($out -split "`r?`n")) {
        $m = [regex]::Match($line, '^\s*\d+\.\s(.+?)\s\s+\[[^\]]+\]\s*(?:#.*)?$')
        if ($m.Success) { $list.Add($m.Groups[1].Value.Trim()) }
    }
    return ,$list
}

function Invoke-Check {
    param([string]$Path = $RulesFile)
    Write-Title ("check  " + $Path)
    $s = Read-EngineRuleSet -Path $Path
    if (-not $s.Exists) { Write-Bad "文件不存在"; return }

    Write-Host ("  文件大小 : {0} 字节" -f $s.ByteLength)
    if ($s.HasBom) { Write-Warn2 "文件带 UTF-8 BOM（引擎会剥掉，通常没问题）" }

    if ($s.IsValidUtf8) {
        Write-Ok "编码 = 合法 UTF-8（与引擎的读取方式一致）"
    } else {
        Write-Bad "文件不是合法 UTF-8 —— 引擎按 UTF-8 读会得到乱码，中文规则会被静默废掉！"
        Write-Info "修法：用 RulesTool.cmd apply <档案名> 重新生成，或把文件另存为 UTF-8 无 BOM。"
    }

    Write-Host ("  物理行数 : {0}" -f $s.PhysicalLines)
    Write-Host ("  非空行数 : {0}" -f $s.NonBlankLines)
    Write-Host ("  生效规则 : {0}   <- 程序日志里应打印「{0} rules have been read.」" -f $s.EffectiveRules.Count) -ForegroundColor Green

    if ($s.Duplicates.Count -gt 0) {
        Write-Warn2 ("有 {0} 行完全重复，被引擎去重后只算一条：" -f $s.Duplicates.Count)
        $s.Duplicates | ForEach-Object { Write-Info ("重复: " + $_) }
    }
    if ($s.WhiteSpaceRules.Count -gt 0) {
        Write-Warn2 "以下规则首尾带空白字符，可能匹配不到（建议去掉）："
        $s.WhiteSpaceRules | ForEach-Object { Write-Info ("[" + $_ + "]") }
    }
    if ($s.MangledRules.Count -gt 0) {
        Write-Bad ("有 {0} 条规则含乱码字符 U+FFFD，永远匹配不到真实服务器名（死规则）：" -f $s.MangledRules.Count)
        $s.MangledRules | ForEach-Object { Write-Info ("乱码: " + $_) }
    }
    if ($s.SuspiciousRules.Count -gt 0) {
        Write-Warn2 ("有 {0} 条规则含中文/ASCII 之外的字符（乱码变体的典型特征，多半匹配不到）：" -f $s.SuspiciousRules.Count)
        $s.SuspiciousRules | ForEach-Object { Write-Info ("可疑: " + $_) }
        Write-Info "若你确实要匹配俄文/希腊文等外文服名，可忽略此警告。"
    }
    if ($s.InvalidRegex.Count -gt 0) {
        Write-Bad "以下行不是合法正则，程序启动时会抛异常："
        $s.InvalidRegex | ForEach-Object { Write-Info $_ }
    }

    Write-Title "生效规则清单"
    $corpus = Get-Corpus
    $hits   = Get-RuleHits -Rules $s.EffectiveRules -Corpus $corpus
    $i = 0
    foreach ($r in $s.EffectiveRules) {
        $i++
        $h = $hits[$r]
        $tag = if ($h -le 0) { '  <- 历史日志中 0 命中' } else { '' }
        Write-Host ("  {0,2}. {1,-30} 命中 {2,5} 次{3}" -f $i, $r, $h, $tag)
    }

    # P1 收敛：本脚本的解析结果必须与引擎（FilterTool.exe --rules）逐条一致
    $cli = Get-EngineRulesViaCli
    if ($null -eq $cli) {
        Write-Info '（跳过引擎一致性核对：FilterTool.exe 不可用）'
    } else {
        $psRules = @($s.EffectiveRules)
        $same = ($cli.Count -eq $psRules.Count)
        if ($same) {
            for ($k = 0; $k -lt $psRules.Count; $k++) {
                if ($cli[$k] -cne $psRules[$k]) { $same = $false; break }
            }
        }
        if ($same) {
            Write-Ok ('引擎解析一致：FilterTool.exe --rules 同样读出 ' + $cli.Count + ' 条生效规则')
        } else {
            Write-Warn2 ('引擎解析不一致：FilterTool.exe --rules 读出 ' + $cli.Count + ' 条，本脚本 ' + $psRules.Count + ' 条')
            foreach ($d in @($cli | Where-Object { $psRules -cnotcontains $_ })) { Write-Info ('仅引擎: ' + $d) }
            foreach ($d in @($psRules | Where-Object { $cli -cnotcontains $_ })) { Write-Info ('仅脚本: ' + $d) }
        }
    }

    # P2-1：引擎侧校验（FilterTool.exe --rules-validate，与 CLI/界面共用同一实现）
    $exe = Join-Path $Root $ExeName
    if (Test-Path -LiteralPath $exe) {
        Write-Title "引擎校验（FilterTool.exe --rules-validate）"
        & $exe --rules-validate
        if ($LASTEXITCODE -eq 0) { Write-Ok "引擎校验通过（编码/BOM/重复/乱码/非法正则/规则文件同步均无问题）" }
        else { Write-Warn2 "引擎校验发现问题（见上）" }
    }
    return $s
}

# 规则 -> 来源档名（如 custom / rpg / pureplus）
function Get-RulesWithSource {
    # V-16: 规则文本按序数（区分大小写）作键，与引擎去重一致
    $map = New-Object 'System.Collections.Generic.Dictionary[string,string]' (, $Ordinal)
    foreach ($comp in ((Get-ActiveProfile) -split '\+')) {
        $name = $comp.Trim()
        if ($name -eq '') { continue }
        $f = Join-Path $ProfileDir ($name + '.txt')
        if (-not (Test-Path -LiteralPath $f)) { continue }
        foreach ($line in [System.IO.File]::ReadAllLines($f, $UTF8NoBom)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $t = $line.Trim()
            if ($t.StartsWith('#')) { continue }
            if ($map.ContainsKey($t)) { $map[$t] = $map[$t] + ',' + $name } else { $map[$t] = $name }
        }
    }
    return $map
}

function Invoke-Test {
    param([string]$Path = $RulesFile)
    Write-Title "test  用历史日志语料评估误伤 / 漏拦"
    $s = Read-EngineRuleSet -Path $Path
    if (-not $s.Exists) { Write-Bad "文件不存在"; return }
    $rules = $s.EffectiveRules
    if ($rules.Count -eq 0) { Write-Warn2 "没有生效规则"; return }

    $corpus = Get-Corpus
    if ($corpus.Count -eq 0) { Write-Warn2 "Logs 里没有语料"; return }

    # 来自 custom.txt 的规则是你自己按名字加的，命中属于"预期内"，不计入误伤
    $srcMap   = Get-RulesWithSource
    $ownRules = @($rules | Where-Object { $srcMap[$_] -and (($srcMap[$_] -split ',') -contains 'custom') })
    $strict   = @($rules | Where-Object { $ownRules -notcontains $_ })

    $rxStrict = @($strict | ForEach-Object { New-Object System.Text.RegularExpressions.Regex($_) })
    $rxAll    = @($rules  | ForEach-Object { New-Object System.Text.RegularExpressions.Regex($_) })
    $isRpgClass = New-Object System.Text.RegularExpressions.Regex('(?i)rpg|(?i)pure')

    $blocked = 0; $blockedEvents = 0
    $missedRpg     = New-Object System.Collections.Generic.List[object]
    $blockedNonRpg = New-Object System.Collections.Generic.List[object]
    $ownOnly       = New-Object System.Collections.Generic.List[object]

    foreach ($c in $corpus) {
        $hitAll = $false
        foreach ($r in $rxAll) { if ($r.IsMatch($c.Name)) { $hitAll = $true; break } }
        if ($hitAll) { $blocked++; $blockedEvents += $c.Count }

        $hitStrict = $false
        foreach ($r in $rxStrict) { if ($r.IsMatch($c.Name)) { $hitStrict = $true; break } }

        if ($isRpgClass.IsMatch($c.Name)) {
            if (-not $hitAll) { $missedRpg.Add($c) }
        } elseif ($hitStrict) {
            $blockedNonRpg.Add($c)
        } elseif ($hitAll) {
            $ownOnly.Add($c)
        }
    }

    Write-Host ("  语料           : {0} 个不同服务器名 / {1} 次拦截记录" -f $corpus.Count, (($corpus | Measure-Object Count -Sum).Sum))
    Write-Host ("  当前规则会拦   : {0} 个名字 / {1} 次" -f $blocked, $blockedEvents)
    Write-Host ''
    Write-Host ("  RPG/Pure 类漏拦 : {0} 个名字" -f $missedRpg.Count) -ForegroundColor $(if ($missedRpg.Count -eq 0) { 'Green' } else { 'Yellow' })
    $missedRpg | Select-Object -First 20 | ForEach-Object { Write-Info ("漏: {0,5}  {1}" -f $_.Count, $_.Name) }
    Write-Host ("  非 RPG 类误拦   : {0} 个名字" -f $blockedNonRpg.Count) -ForegroundColor $(if ($blockedNonRpg.Count -eq 0) { 'Green' } else { 'Yellow' })
    $blockedNonRpg | Select-Object -First 25 | ForEach-Object { Write-Info ("误: {0,5}  {1}" -f $_.Count, $_.Name) }
    if ($blockedNonRpg.Count -gt 25) { Write-Info ("...（其余 {0} 个省略）" -f ($blockedNonRpg.Count - 25)) }
    if ($ownOnly.Count -gt 0) {
        Write-Host ("  你自己的名字规则命中 : {0} 个名字（预期内，不计误伤）" -f $ownOnly.Count) -ForegroundColor Green
        $ownOnly | Select-Object -First 8 | ForEach-Object { Write-Info ("己: {0,5}  {1}" -f $_.Count, $_.Name) }
    }
    Write-Host ''
    Write-Info "说明：来自 custom.txt 的规则是你要拦的具体服名，命中算预期内；误伤只统计其它规则档。"
}

function Invoke-Profiles {
    Write-Title "profiles  规则文件（规则已统一：rules-profiles\custom.txt；旧档位已归档 rules-profiles\archive\）"
    if (-not (Test-Path -LiteralPath $ProfileDir)) { Write-Bad "没有 rules-profiles 目录"; return }
    $activeName = Get-ActiveProfile
    $activeSet  = @($activeName -split '\+' | ForEach-Object { $_.Trim() })
    Write-Host ("  当前启用: " + $activeName) -ForegroundColor Green
    Write-Host ''
    foreach ($f in Get-ChildItem -LiteralPath $ProfileDir -Filter *.txt | Sort-Object Name) {
        $name  = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
        $rules = Get-ProfileRules -Name $name
        $mark  = ''
        if ($activeSet -contains $name) { $mark = '   <== 已启用' }
        Write-Host ("  {0,-10} {1,2} 条规则{2}" -f $name, $rules.Count, $mark)
    }
    Write-Host ''
    Write-Info "统一后只需：RulesTool.cmd apply custom（旧档位文件已归档，不再参与生成）"
    Write-Info "加单条新规则最快：RulesTool.cmd add `"服务器完整名字`""
}

function Invoke-Apply {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { Write-Bad "用法: RulesTool.cmd apply custom（规则已统一，只有 custom 一个规则文件）"; return }

    Write-Title ("apply  " + $Name)
    # P2-1：写入路径统一在 FilterTool.exe --rules-apply（Engine.ApplyProfile：校验规则→备份→生成→写 block_rules.txt）。
    # 只有找不到 FilterTool.exe 时才回退到脚本内的旧实现。
    $exe = Join-Path $Root $ExeName
    if (Test-Path -LiteralPath $exe) {
        & $exe --rules-apply $Name
        $code = $LASTEXITCODE
        Write-Host ''
        if ($code -eq 0) {
            Write-Ok "block_rules.txt 已由引擎生成（与脚本/界面共用同一实现）"
            $null = Invoke-Check -Path $RulesFile
        } else {
            Write-Bad ("apply 失败（退出码 {0}）" -f $code)
        }
        Write-Host ''
        Write-Warn2 "规则在程序【启动时】读入。请执行：RulesTool.cmd restart   或到托盘菜单点「重载规则」"
        return
    }
    Write-Warn2 "找不到 FilterTool.exe，回退到脚本内实现"
    $rules = Get-ProfileRules -Name $Name
    if ($rules.Count -eq 0) { Write-Bad "该规则档没有有效规则"; return }

    $bak = Backup-Rules -Path $RulesFile
    if ($bak) { Write-Ok ("已备份旧文件: " + (Split-Path -Leaf $bak)) }

    $written = Write-RulesFile -Rules $rules -Path $RulesFile
    Set-ActiveProfile -Name $Name
    Write-Ok ("已写入 {0} 条规则 -> {1}" -f $written.Count, $RulesFile)
    Write-Host ''
    $null = Invoke-Check -Path $RulesFile
    Write-Host ''
    Write-Warn2 "规则在程序【启动时】读入。请执行：RulesTool.cmd restart   或到托盘菜单点「重载规则」"
}

# 一条命令加规则：add "服务器完整名字" [loose] [restart]
function Invoke-Add {
    param([string]$Name, [string[]]$Options = @())
    if ([string]::IsNullOrWhiteSpace($Name)) {
        Write-Bad '用法: RulesTool.cmd add "服务器完整名字" [loose] [restart]'
        Write-Info '  loose   : 把名字里的数字当通配（\d+），能一并盖住同族服'
        Write-Info '  restart : 加完立刻重启程序生效'
        Write-Info '例: RulesTool.cmd add "【CN】102.纯净三方" loose restart'
        return
    }
    Write-Title ("add  " + $Name)
    $loose   = ($Options -contains 'loose')
    $doStart = ($Options -contains 'restart')

    # P2-1：加规则统一在 FilterTool.exe --rules-add（Engine.AddCustomRule：生成→已覆盖判断→追加→备份→重建→可选重启）。
    $exe = Join-Path $Root $ExeName
    if (Test-Path -LiteralPath $exe) {
        $cliArgs = @('--rules-add', $Name) + @($Options)
        & $exe @cliArgs
        $code = $LASTEXITCODE
        Write-Host ''
        if ($code -eq 0) { Write-Ok "add 已完成（引擎 与脚本/界面共用同一实现）" }
        else { Write-Bad ("add 失败（退出码 {0}）" -f $code) }
        if (-not $doStart) { Write-Warn2 "执行 RulesTool.cmd restart（或托盘「重载规则」）后生效" }
        return
    }
    Write-Warn2 "找不到 FilterTool.exe，回退到脚本内实现"
    $rule = New-RuleFromName -Name $Name -Loose:$loose
    Write-Info ("生成规则: " + $rule)

    # 已经能被拦到的话就不必加
    $cur = Read-EngineRuleSet -Path $RulesFile
    foreach ($r in $cur.EffectiveRules) {
        try {
            if ((New-Object System.Text.RegularExpressions.Regex($r)).IsMatch($Name)) {
                Write-Ok ("这个名字已经被规则 [" + $r + "] 拦住了，无需新增。")
                return
            }
        } catch { }
    }

    # 确保 custom 档存在
    if (-not (Test-Path -LiteralPath $CustomProfile)) {
        $head = @(
            '# ============================================================',
            '# 规则档 custom  ——  由 RulesTool.cmd add 自动追加',
            '# ============================================================',
            '# 这里是你一条条加进来的"精确规则"（只匹配指定的服务器名）。',
            '# 想删掉某条，删掉对应那一行，再执行 RulesTool.cmd apply rpg+custom',
            '# ============================================================',
            ''
        ) -join "`r`n"
        [System.IO.File]::WriteAllText($CustomProfile, $head, $UTF8NoBom)
    }

    $existing = Get-ProfileRules -Name 'custom'
    if ($existing -ccontains $rule) {
        Write-Warn2 "custom 档里已经有这条规则了，无需重复添加。"
    } else {
        $stamp  = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        $append = "`r`n# {0}  ({1})`r`n{2}`r`n" -f $Name, $stamp, $rule
        [System.IO.File]::AppendAllText($CustomProfile, $append, $UTF8NoBom)
        Write-Ok "已追加到 rules-profiles\custom.txt"
    }

    # 启用：在当前档组合上叠加 custom
    $active = Get-ActiveProfile
    if (($active -split '\+') -notcontains 'custom') { $active = $active + '+custom' }
    Write-Host ''
    $null = Invoke-Apply -Name $active

    if ($doStart) {
        Write-Host ''
        Invoke-Restart
    } else {
        Write-Host ''
        Write-Warn2 "执行 RulesTool.cmd restart（或托盘「重载规则」）后生效"
    }
}

function Invoke-Status {
    Write-Title "status"
    # 生命周期（进程 / 计划任务 / 旧入口）唯一实现在 FilterTool.exe --lifecycle status。
    $exe = Join-Path $Root $ExeName
    if (Test-Path -LiteralPath $exe) { & $exe --lifecycle status }
    else { Write-Warn2 ("找不到 " + $exe + "，无法查询生命周期；规则信息如下") }

    $s = Read-EngineRuleSet -Path $RulesFile
    if ($s.Exists) {
        $enc = if ($s.IsValidUtf8) { 'UTF-8 (正常)' } else { '非 UTF-8 (会被读成乱码!)' }
        Write-Host ("  block_rules.txt : {0} 条生效规则，编码 {1}" -f $s.EffectiveRules.Count, $enc) -ForegroundColor $(if ($s.IsValidUtf8) { 'Green' } else { 'Red' })
    }
    if (Test-Path -LiteralPath $LogDir) {
        $today = Join-Path $LogDir ((Get-Date).ToString('yyyy-MM-dd') + '.log')
        if (Test-Path -LiteralPath $today) {
            $txt = Read-TextShared $today
            $n   = ([regex]'Block server with name:').Matches($txt).Count
            Write-Host ("  今日 ({0}) 已拦服务器名 {1} 次" -f (Get-Date).ToString('yyyy-MM-dd'), $n)
        }
    }
}

function Invoke-Logs {
    param([int]$Tail = 25)
    Write-Title "logs"
    if (-not (Test-Path -LiteralPath $LogDir)) { Write-Bad "没有 Logs 目录"; return }
    $last = Get-ChildItem -LiteralPath $LogDir -Filter *.log | Sort-Object Name | Select-Object -Last 1
    if (-not $last) { Write-Bad "Logs 是空的"; return }
    Write-Host ("  文件: " + $last.FullName)
    $txt   = Read-TextShared $last.FullName
    $lines = $txt -split "`r`n|`n|`r"
    $rules = @($lines | Where-Object { $_ -match 'rules have been read' } | Select-Object -Last 3)
    foreach ($r in $rules) { Write-Host ("  " + $r.Trim()) -ForegroundColor Green }
    Write-Host ''
    $lines | Select-Object -Last $Tail | ForEach-Object { Write-Host ("  " + $_.TrimEnd()) }
}

function Invoke-Restart {
    Write-Title "restart  结束并重新启动 FilterTool 常驻拦截"
    # 生命周期唯一实现在 FilterTool.exe --lifecycle restart（进程结束、计划任务启动、回退直接启动、等待与日志判定）。
    $exe = Join-Path $Root $ExeName
    if (-not (Test-Path -LiteralPath $exe)) { Write-Bad ("找不到 " + $exe); return }
    & $exe --lifecycle restart
    if ($LASTEXITCODE -eq 0) { Write-Ok "常驻拦截已在运行" }
    else { Write-Warn2 "常驻拦截未确认启动，请手动确认（多半需要管理员权限）" }
}

function Invoke-Backup {
    Write-Title "backup"
    # P2-1：备份统一在 FilterTool.exe --rules-backup（Engine.BackupRules → rules-profiles\.backup\）
    $exe = Join-Path $Root $ExeName
    if (Test-Path -LiteralPath $exe) {
        & $exe --rules-backup
        if ($LASTEXITCODE -eq 0) { return }
        Write-Bad "引擎备份失败，回退到脚本内实现"
    }
    $bak = Backup-Rules -Path $RulesFile
    if ($bak) { Write-Ok ("已备份: " + (Split-Path -Leaf $bak)) } else { Write-Bad "block_rules.txt 不存在" }
}

function Invoke-Backups {
    Write-Title "backups  可用的 block_rules.txt 备份"
    # 旧脚本把备份放在根目录；P2-1 之后引擎写到 rules-profiles\.backup\，两处都列出来。
    $list = @(@(
        Get-ChildItem -LiteralPath $BackupDir -Filter 'block_rules.txt.*.bak' -File -ErrorAction SilentlyContinue
        Get-ChildItem -LiteralPath $Root     -Filter 'block_rules.txt.*.bak' -File -ErrorAction SilentlyContinue
    ) | Sort-Object LastWriteTime -Descending)
    if ($list.Count -eq 0) { Write-Warn2 "没有备份文件"; return }
    $i = 0
    foreach ($f in $list) {
        $i++
        Write-Host ("  {0,2}. {1,-44} {2,5} 字节  {3}" -f $i, $f.Name, $f.Length, $f.LastWriteTime)
    }
    Write-Host ''
    Write-Info "恢复某个备份：RulesTool.cmd restore <文件名>"
}

function Invoke-Restore {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) {
        Write-Bad '用法: RulesTool.cmd restore <备份文件名>   （先用 RulesTool.cmd backups 查看）'
        return
    }
    $sysRoot = Join-Path $Root $Name
    $sysBak  = Join-Path $BackupDir $Name
    $path = $null
    if (Test-Path -LiteralPath $sysRoot) { $path = $sysRoot }
    elseif (Test-Path -LiteralPath $sysBak) { $path = $sysBak }
    if (-not $path -and $Name.Contains('\')) { if (Test-Path -LiteralPath $Name) { $path = $Name } }
    if (-not $path) { Write-Bad ("找不到备份: " + $Name + "（已查 " + $sysRoot + " 和 " + $sysBak + "）"); return }

    Write-Title ("restore  " + $Name)
    # P2-1：恢复统一在 FilterTool.exe --rules-restore（先备份当前文件再原子写）
    $exe = Join-Path $Root $ExeName
    if (Test-Path -LiteralPath $exe) {
        & $exe --rules-restore $path
        if ($LASTEXITCODE -eq 0) {
            Write-Host ''
            $null = Invoke-Check -Path $RulesFile
            Write-Host ''
            Write-Warn2 "执行 RulesTool.cmd restart 后生效"
            return
        }
        Write-Bad "引擎恢复失败，回退到脚本内实现"
    }
    $cur = Backup-Rules -Path $RulesFile
    if ($cur) { Write-Ok ("已先备份当前文件: " + (Split-Path -Leaf $cur)) }
    Copy-Item -LiteralPath $path -Destination $RulesFile -Force
    Write-Ok "已恢复。"
    Write-Host ''
    $null = Invoke-Check -Path $RulesFile
    Write-Host ''
    Write-Warn2 "执行 RulesTool.cmd restart 后生效"
}

# 查某个服务器名为什么被拦 / 为什么没被拦，并给出精确规则建议
function Invoke-Why {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) {
        Write-Bad '用法: RulesTool.cmd why "服务器名"'
        Write-Info '例如: RulesTool.cmd why "[AC]X4纯净RPG★正常服"'
        return
    }
    Write-Title ("why  " + $Name)
    $s = Read-EngineRuleSet -Path $RulesFile
    $hit = New-Object System.Collections.Generic.List[string]
    foreach ($r in $s.EffectiveRules) {
        try { if ((New-Object System.Text.RegularExpressions.Regex($r)).IsMatch($Name)) { $hit.Add($r) } } catch { }
    }
    if ($hit.Count -gt 0) {
        Write-Ok ("会被拦截 —— 命中 {0} 条规则：" -f $hit.Count)
        foreach ($r in $hit) { Write-Info ("  " + $r) }
    } else {
        Write-Warn2 "当前规则【不会】拦截这个服务器名（会出现在服务器列表里）"
        $exact = New-RuleFromName -Name $Name
        $loose = New-RuleFromName -Name $Name -Loose
        Write-Host ''
        Write-Info "一条命令把它拦掉（精确版）："
        Write-Host ('    RulesTool.cmd add "{0}" restart' -f $Name) -ForegroundColor Green
        if ($loose -ne $exact) {
            Write-Info "如果要一并盖住同族服（数字当通配）："
            Write-Host ('    RulesTool.cmd add "{0}" loose restart' -f $Name) -ForegroundColor Green
        }
        Write-Host ''
        Write-Info ("对应正则  精确: " + $exact)
        if ($loose -ne $exact) { Write-Info ("对应正则  宽松: " + $loose) }
    }
}

function Show-Help {
    Write-Host @"
SteamServerFilter 规则工具

  RulesTool.cmd status              查看程序/计划任务/当前规则状态
  RulesTool.cmd check [文件]        精确模拟引擎，报告生效规则数、重复行、乱码死规则
  RulesTool.cmd test  [文件]        用 Logs 里的历史语料评估漏拦与误拦
  RulesTool.cmd why "<服务器名>"    查这个名字为什么被拦/没被拦，并给出精确规则建议
  RulesTool.cmd add "<服务器名>" [loose] [restart]
                                    一条命令加规则（写进 rules-profiles\custom.txt 并启用）
  RulesTool.cmd profiles            列出可用规则档（含当前启用组合）
  RulesTool.cmd apply <档名>        生成 block_rules.txt（自动备份 + 校验）
  RulesTool.cmd backup              备份当前 block_rules.txt
  RulesTool.cmd backups             列出所有备份
  RulesTool.cmd restore <文件名>    恢复到某个备份（会先自动备份当前文件）
  RulesTool.cmd logs [行数]         看最新日志与启动时的规则条数
  RulesTool.cmd cleanlogs [天数]    -> 转调 FilterTool.exe --logs-prune（唯一入口；保留天数见 config.ini log-keep）
  RulesTool.cmd restart             结束进程并通过计划任务重启（需管理员）

规则档可组合：apply rpg / apply rpg+cn / apply rpg+playmode / apply rpg+cn+playmode / apply rpg+brands
规则档在 rules-profiles\ 目录，可自行编辑（那里支持 '#' 注释，生成时会自动剥掉）。

重要：block_rules.txt 必须是【UTF-8 无 BOM】，且【不能有注释行】——
      引擎会把每一非空行都当正则，'#' 行也会被当成规则！
"@
}

# ---------------------------------------------------------------- dispatch
switch ($Command.ToLower()) {
    'status'   { Invoke-Status }
    'check'    { if ([string]::IsNullOrWhiteSpace($Arg)) { $null = Invoke-Check } else { $null = Invoke-Check -Path $Arg } }
    'test'     { if ([string]::IsNullOrWhiteSpace($Arg)) { Invoke-Test } else { Invoke-Test -Path $Arg } }
    'profiles' { Invoke-Profiles }
    'apply'    { Invoke-Apply -Name $Arg }
    'add'      { Invoke-Add -Name $Arg -Options $Rest }
    'backup'   { Invoke-Backup }
    'backups'  { Invoke-Backups }
    'restore'  { Invoke-Restore -Name $Arg }
    'logs'     {
        $t = 25
        if ($Arg -match '^\d+$') { $t = [int]$Arg }
        Invoke-Logs -Tail $t
    }
    'cleanlogs' {
        # 4.3 尾巴：日志清理统一到 FilterTool.exe --logs-prune（唯一入口、唯一默认天数）。
        # 本命令保留为跳转提示，避免 cleanlogs 默认 90 天 / --logs-prune 默认 30 天两套数字让人困惑。
        Write-Title 'cleanlogs 已并入 FilterTool.exe --logs-prune'
        $prune = Join-Path $PSScriptRoot 'FilterTool.exe'
        if (-not (Test-Path -LiteralPath $prune)) {
            Write-Bad ('找不到 ' + $prune + ' —— 请直接用 FilterTool.exe --logs-prune')
            return
        }
        $ftArgs = @('--logs-prune')
        if ($Arg -match '^\d+$') { $ftArgs += $Arg }
        Write-Host ('  转调：FilterTool.exe ' + ($ftArgs -join ' ')) -ForegroundColor DarkGray
        Write-Host '  保留天数取自 config.ini 的 log-keep（FilterTool.exe --config 可查）' -ForegroundColor DarkGray
        & $prune @ftArgs
        Write-Host '  定时清理由计划任务 SteamServerFilter Log Cleanup 负责（每 3 天，--logs-task 开关）' -ForegroundColor DarkGray
    }
    'restart'  { Invoke-Restart }
    'why'      { Invoke-Why -Name $Arg }
    'help'     { Show-Help }
    '-h'       { Show-Help }
    '--help'   { Show-Help }
    default    { Write-Bad ("未知命令: " + $Command); Show-Help }
}
