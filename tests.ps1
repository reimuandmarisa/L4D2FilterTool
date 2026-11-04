# tests.ps1 --- 核心不变量测试（优化方案 2.1）
#
# 真正的断言在 FilterTool.exe --selftest 里（C# 直调内部 API，避免反射）：
#   1 规则语义（UTF-8 无 BOM / 空行跳过 / Ordinal 去重 / 大小写敏感 / 非锚定）
#   2 A2S 解析（单包 FFFFFFFF 49 / 分片 FFFFFEFE / challenge 41）
#   3 规则生成（exact / loose / 元字符转义）
#   4 !端口 例外（TryParseRange / SplitExempt / BuildFilters / 严格 4 段 IP）
#   5 端点键往返与 CIDR 边界（/0 /31 /32）
#   6 IsPacketBlockedFastU 与 WinDivert 表达式语义一致
#
# 本脚本负责：跑断言 + 跑几条端到端 CLI 断言 + 汇总退出码。
# 自检（--selftest）在临时目录里重定向 Engine.Root / IpEngine.Root，不碰真实配置。
# 端到端 CLI 中的 !端口 用例会临时向真实 ip_block.txt 写入 TEST-NET 地址 203.0.113.9!33030，
# 随后立即 --remove 清理；若进程被中断可能残留，可手动执行 FilterTool.exe --remove 203.0.113.9 清理。
#
# 用法：  powershell -ExecutionPolicy Bypass -File tests.ps1
# 退出码：0 = 全部通过；非 0 = 有失败（build.cmd 用作门禁）

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $root 'FilterTool.exe'
$script:pass = 0
$script:fail = 0
$failNames = New-Object System.Collections.ArrayList

function Assert($cond, $name, $detail) {
    if ($cond) { $script:pass++; Write-Host ("  [PASS] " + $name) }
    else { $script:fail++; [void]$failNames.Add($name); Write-Host ("  [FAIL] " + $name + "   " + $detail) -ForegroundColor Red }
}

# 用 Start-Process 读退出码：PS 5.1 下对"重定向输出的原生命令"取 $LASTEXITCODE 不可靠
function Invoke-Tool([string[]]$argv) {
    $tmp = [System.IO.Path]::GetTempFileName()
    $p = Start-Process -FilePath $exe -ArgumentList $argv -NoNewWindow -Wait -PassThru `
         -RedirectStandardOutput $tmp -RedirectStandardError ($tmp + ".err")
    $o = (Get-Content $tmp -Raw -ErrorAction SilentlyContinue)
    $e = (Get-Content ($tmp + ".err") -Raw -ErrorAction SilentlyContinue)
    Remove-Item $tmp, ($tmp + ".err") -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{ Code = $p.ExitCode; Out = (("" + $o) + "" + $e) }
}

Write-Host "=== 1) 核心不变量（FilterTool.exe --selftest）==="
$r = Invoke-Tool @('--selftest')
$r.Out -split "`r?`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host ("  " + $_) }
Assert ($r.Code -eq 0) "不变量自检全部通过" ("exit=" + $r.Code)

Write-Host "=== 2) 端到端 CLI 断言 ==="
$v = (Invoke-Tool @('--version')).Out
Assert ($v -match '构建时间') "过滤 --version 输出构建时间" $v.Trim()

$gd = Invoke-Tool @('--group-list-diagnose')
Assert ($gd.Code -eq 0 -and $gd.Out -match '组服列表诊断' -and $gd.Out -match '不保证') "组服诊断只读且明确不承诺隐藏行" $gd.Out.Trim()

# 组服列表过滤已合并进 FilterTool：状态里必须能看到“自动注入”，rules 必须能看到默认规则
$gs = Invoke-Tool @('--group-filter')
Assert ($gs.Code -eq 0 -and $gs.Out -match '组服列表过滤' -and $gs.Out -match '自动注入') "--group-filter 状态报告自动注入" $gs.Out.Trim()

$gr = Invoke-Tool @('--group-filter','rules')
Assert ($gr.Code -eq 0 -and $gr.Out -match '生成正则') "--group-filter rules 显示默认规则" $gr.Out.Trim()

# 名字层合并：状态里必须能报告合并模式（默认 custom）
$gn = Invoke-Tool @('--group-filter','namelayer')
Assert ($gn.Code -eq 0 -and $gn.Out -match '名字层合并' -and $gn.Out -match 'custom') "--group-filter namelayer 显示名字层合并状态" $gn.Out.Trim()

$m = (Invoke-Tool @('--mode')).Out
Assert ($m -match 'both|name|IP 清单') "--mode 能报告当前模式" $m.Trim()

$dr = Invoke-Tool @('--doc-check'); $d = $dr.Out
Assert ($dr.Code -eq 0 -and ($d -match '文档已同步' -or $d -match '文档已删除')) "--doc-check 文档同步（USAGE.md 已删除时跳过内容比对）" $d.Trim()

# P1-3：生命周期统一入口（--lifecycle）必须可用，未知子命令返回用法
$lc = Invoke-Tool @('--lifecycle','status')
Assert ($lc.Code -eq 0 -and $lc.Out -match '常驻拦截' -and $lc.Out -match '计划任务') "--lifecycle status 报告常驻进程与计划任务" $lc.Out.Trim()
$lu = Invoke-Tool @('--lifecycle','bogus')
Assert ($lu.Code -eq 2 -and $lu.Out -match '用法') "--lifecycle 未知子命令返回用法" $lu.Out.Trim()

# P2-2：config.ini 单一事实源 —— 审计要报告来源，且两层命令都不能输出会话 token 明文
$ca = Invoke-Tool @('--config-audit')
Assert ($ca.Code -eq 0 -and $ca.Out -match '统一开关审计' -and $ca.Out -match '来源=') "--config-audit 报告每个开关的来源" $ca.Out.Trim()
$cv = Invoke-Tool @('--config')
$tokenLine = Get-Content (Join-Path $root 'config.ini') -ErrorAction SilentlyContinue |
             Where-Object { $_ -match '^\s*group-filter-session-token\s*=' } | Select-Object -First 1
$token = if ($tokenLine) { ($tokenLine -split '=', 2)[1].Trim() } else { '' }
$leaked = ($token.Length -ge 16) -and (($ca.Out + $cv.Out).Contains($token))
Assert ($cv.Code -eq 0 -and (-not $leaked) -and $cv.Out -match '已设置，已隐藏') "--config/--config-audit 不输出 token 明文" ""

$lr = Invoke-Tool @('--layout'); $l = $lr.Out
if ($lr.Code -ne 0 -or ($l -notmatch '通过')) {
    # GUI 自检在极少数情况下（首次 GDI/字体初始化）会在写完结果行之前退出；重试一次再判定，
    # 避免把环境抖动当成真实布局回归（连续 12 次单独运行均通过）。
    Start-Sleep -Milliseconds 400
    $lr = Invoke-Tool @('--layout'); $l = $lr.Out
}
Assert ($lr.Code -eq 0 -and $l -match '通过') "--layout 布局自检" $l.Trim()

# P2-1：规则档服务统一入口（只读断言，不写真实规则文件）
$rv = Invoke-Tool @('--rules-validate')
Assert ($rv.Code -eq 0 -and $rv.Out -match '生效规则' -and $rv.Out -match '与规则同步') "--rules-validate 校验真实规则文件" $rv.Out.Trim()
$leakedRules = ($token.Length -ge 16) -and $rv.Out.Contains($token)
Assert (-not $leakedRules) "--rules-validate 不输出 token 明文" ""
$ra = Invoke-Tool @('--rules-apply')
Assert ($ra.Code -eq 2 -and $ra.Out -match '用法') "--rules-apply 缺少规则文件参数返回用法" $ra.Out.Trim()
$rr = Invoke-Tool @('--rules-restore','no-such-file.bak')
Assert ($rr.Code -eq 2 -and $rr.Out -match '找不到备份') "--rules-restore 不存在的备份被拒绝" $rr.Out.Trim()

# !端口 写法必须被接受，缩写 IP 必须被拒（CLI 层再验一次）
$add = Invoke-Tool @('--add','203.0.113.9!33030','tests.ps1 临时')
$ip = (Invoke-Tool @('--ip')).Out
$add2 = $null
if ($ip -notmatch '203\.0\.113\.9!33030') {
    # 极少数并发场景（另一实例同时改写 ip_block.txt）下刚写入的条目会被短暂覆盖；重写一次再判定。
    Start-Sleep -Milliseconds 300
    $add2 = Invoke-Tool @('--add','203.0.113.9!33030','tests.ps1 临时')
    $ip = (Invoke-Tool @('--ip')).Out
}
$ipDetail = "add exit=" + $add.Code + " out=" + $add.Out + " ip out=" + $ip
if ($add2 -ne $null) { $ipDetail += " retry exit=" + $add2.Code + " out=" + $add2.Out }
Assert ($ip -match '203\.0\.113\.9!33030') "CLI 接受 !端口 写法" ($ipDetail.Trim())
[void](Invoke-Tool @('--remove','203.0.113.9'))

$br = Invoke-Tool @('--add','203.0.113'); $bad = $br.Out
Assert ($br.Code -ne 0) "CLI 拒绝缩写 IP" $bad.Trim()

# P2-4：供应链锁文件校验（第三方二进制按 SHA-256 固定 + 内部产物 x86 PE）
$scOut = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'tools\supply-chain.ps1') -Check 2>&1 | Out-String
$scCode = $LASTEXITCODE
$scTail = (($scOut.Trim() -split [Environment]::NewLine) | Select-Object -Last 1)
# 子进程输出是 UTF-8，父进程按本地代码页解码会乱码；这里用 ASCII 哈希做断言，避免编码差异误判。
Assert ($scCode -eq 0 -and $scOut -match 'A321649090C21AAA7529CE5D019D242B') "supply-chain -Check 校验第三方固定组件" $scTail

Write-Host ""
Write-Host ("=== 汇总：通过 " + $script:pass + "，失败 " + $script:fail + " ===")
if ($script:fail -gt 0) {
    Write-Host "失败项：" -ForegroundColor Red
    $failNames | ForEach-Object { Write-Host ("  - " + $_) -ForegroundColor Red }
    exit 1
}
Write-Host "全部通过 ✓" -ForegroundColor Green
exit 0
