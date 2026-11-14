<#
.SYNOPSIS
    FilterTool.exe 的 Authenticode 签名与校验（自签证书，开发/内测用）。

.DESCRIPTION
    -Sign        给 PE 文件做 Authenticode 签名（默认 FilterTool.exe）。
                 优先使用 -Thumbprint 指定的证书，其次按 -Subject 在证书存储里找，
                 都找不到时自动创建一张自签代码签名证书（CurrentUser\My）。
    -Verify      校验签名。接受两种情况：
                   1) 状态 Valid（证书链受信任）；
                   2) 状态 UnknownError 且原因是根证书不受信任，但签名者指纹与预期一致
                      （自签证书的常见情况；可用 -Trust 把证书装进当前用户根存储后变成 Valid）。
    -CreateCert  只创建/导出证书，不签名。
    -Trust       把证书加入当前用户 Root + TrustedPublisher（仅本机；可能弹 Windows 安全警告）。

    证书默认导出为 tools\certs\SteamServerFilter-CodeSigning.cer（公钥，可随包分发）。
    PFX（含私钥）不要放进仓库，发布脚本会把它当敏感文件拦截。

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\sign.ps1 -CreateCert
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\sign.ps1 -Sign
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\sign.ps1 -Verify
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\sign.ps1 -Sign -PfxPath C:\keys\ssf.pfx -PfxPassword secret
#>
[CmdletBinding()]
param(
    [switch]$Sign,
    [switch]$Verify,
    [switch]$CreateCert,
    [string]$FilePath = '',
    [string]$Subject = 'CN=SteamServerFilter Dev',
    [string]$Thumbprint = '',
    [string]$PfxPath = '',
    [string]$PfxPassword = '',
    [switch]$Trust
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }

$Root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = (Get-Location).Path }
$CertDir = Join-Path $Root 'tools\certs'
$CerPath = Join-Path $CertDir 'SteamServerFilter-CodeSigning.cer'

if ([string]::IsNullOrWhiteSpace($FilePath)) { $FilePath = Join-Path $Root 'FilterTool.exe' }
$FilePath = [System.IO.Path]::GetFullPath($FilePath)

if (-not $Sign -and -not $Verify -and -not $CreateCert) { $Verify = $true }

function Write-Head([string]$text) { Write-Host ''; Write-Host ('== ' + $text + ' ==') }

function Resolve-Certificate {
    if ($Thumbprint -ne '') {
        $clean = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
        foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
            $found = Get-ChildItem -Path $store -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $clean } | Select-Object -First 1
            if ($found) { return $found }
        }
        throw ('找不到指纹为 ' + $Thumbprint + ' 的证书（CurrentUser\My / LocalMachine\My）')
    }
    if ($PfxPath -ne '') {
        if (-not (Test-Path -LiteralPath $PfxPath)) { throw ('找不到 PFX: ' + $PfxPath) }
        $sec = ConvertTo-SecureString -String $PfxPassword -AsPlainText -Force
        return (Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation 'Cert:\CurrentUser\My' -Password $sec)
    }
    $existing = Get-ChildItem -Path 'Cert:\CurrentUser\My' -CodeSigningCert -ErrorAction SilentlyContinue | Where-Object { $_.Subject -eq $Subject } | Sort-Object NotAfter -Descending | Select-Object -First 1
    if ($existing) { return $existing }
    Write-Host ('未找到代码签名证书，创建自签证书: ' + $Subject)
    if (-not (Test-Path -LiteralPath $CertDir)) { New-Item -ItemType Directory -Path $CertDir -Force | Out-Null }
    return (New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject -CertStoreLocation 'Cert:\CurrentUser\My' -KeyUsage DigitalSignature -KeyExportPolicy Exportable -HashAlgorithm SHA256 -KeyLength 2048 -NotAfter (Get-Date).AddYears(3))
}

function Export-PublicCert($cert) {
    if (-not (Test-Path -LiteralPath $CertDir)) { New-Item -ItemType Directory -Path $CertDir -Force | Out-Null }
    Export-Certificate -Cert $cert -FilePath $CerPath -Type CERT | Out-Null
    Write-Host ('[OK] 公钥证书已导出: ' + $CerPath)
    Write-Host ('     指纹: ' + $cert.Thumbprint)
    Write-Host ('     主体: ' + $cert.Subject)
    Write-Host ('     有效期至: ' + $cert.NotAfter.ToString('yyyy-MM-dd'))
}

function Install-Trust($cert) {
    try {
        Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\CurrentUser\TrustedPublisher' | Out-Null
        Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
        Write-Host '[OK] 证书已加入当前用户 Root / TrustedPublisher（仅本机）'
    } catch {
        Write-Host ('[WARN] 安装信任失败（不影响签名，Verify 仍接受签名有效但根不受信任）: ' + $_.Exception.Message)
    }
}

function Stop-ResidentIfNeeded {
    $procs = @(Get-Process -Name 'FilterTool' -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID })
    if ($procs.Count -eq 0) { return $false }
    Write-Host ('[WARN] 常驻 FilterTool 正在运行（PID ' + (($procs | ForEach-Object { $_.Id }) -join ',') + '），先停止以便写入签名')
    foreach ($proc in $procs) { try { Stop-Process -Id $proc.Id -Force -ErrorAction Stop } catch { Write-Host ('[WARN] 停止 PID ' + $proc.Id + ' 失败: ' + $_.Exception.Message) } }
    Start-Sleep -Seconds 2
    return $true
}

function Start-ResidentIfNeeded {
    $exe = Join-Path $Root 'FilterTool.exe'
    if (-not (Test-Path -LiteralPath $exe)) { return }
    $task = 'SteamServerFilter IP Block'
    & schtasks /Run /TN $task *> $null
    if ($LASTEXITCODE -eq 0) {
        Start-Sleep -Seconds 2
        $alive = @(Get-Process -Name 'FilterTool' -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID })
        if ($alive.Count -gt 0) { Write-Host '[OK] 常驻进程已通过计划任务重启' ; return }
    }
    Start-Process -FilePath $exe -ArgumentList '--run' | Out-Null
    Write-Host '[OK] 已用 FilterTool.exe --run 重启常驻进程'
}

function Find-ExpectedThumb([string]$expectedThumb) {
    if (-not [string]::IsNullOrWhiteSpace($expectedThumb)) { return ($expectedThumb -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() }
    $own = Get-ChildItem -Path 'Cert:\CurrentUser\My' -CodeSigningCert -ErrorAction SilentlyContinue | Where-Object { $_.Subject -eq $Subject } | Select-Object -First 1
    if ($own) { return $own.Thumbprint }
    return ''
}

function Test-Signature([string]$path, [string]$expectedThumb) {
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Host ('[FAIL] 文件不存在: ' + $path) -ForegroundColor Red
        return $false
    }
    $sig = Get-AuthenticodeSignature -FilePath $path
    Write-Host ('文件: ' + $path)
    Write-Host ('大小: ' + (Get-Item -LiteralPath $path).Length + ' 字节')
    Write-Host ('SHA-256: ' + (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant())
    Write-Host ('签名状态: ' + $sig.Status)
    if ($sig.StatusMessage) { Write-Host ('状态说明: ' + $sig.StatusMessage) }
    if (-not $sig.SignerCertificate) {
        Write-Host '[FAIL] 文件没有 Authenticode 签名' -ForegroundColor Red
        return $false
    }
    Write-Host ('签名者: ' + $sig.SignerCertificate.Subject)
    Write-Host ('签名者指纹: ' + $sig.SignerCertificate.Thumbprint)
    if ($sig.TimeStamperCertificate) { Write-Host ('时间戳: ' + $sig.TimeStamperCertificate.Subject) }
    $expect = Find-ExpectedThumb $expectedThumb
    if ($sig.Status -eq 'Valid') {
        Write-Host '[OK] 签名有效（证书链受信任）' -ForegroundColor Green
        return $true
    }
    if ($sig.Status -eq 'UnknownError' -and $sig.StatusMessage -match 'not trusted|不受信任|根证书|root certificate') {
        if ($expect -eq '' -or $sig.SignerCertificate.Thumbprint -eq $expect) {
            Write-Host '[OK] 签名完整有效，但自签根证书不在受信任存储（可 -Trust 或分发 .cer 手动信任）' -ForegroundColor Green
            return $true
        }
        Write-Host ('[FAIL] 签名者指纹与预期不一致（预期 ' + $expect + '）') -ForegroundColor Red
        return $false
    }
    Write-Host '[FAIL] 签名校验未通过' -ForegroundColor Red
    return $false
}

Write-Host '=== SteamServerFilter Authenticode 签名工具 ==='

if ($CreateCert) {
    Write-Head '创建/导出代码签名证书'
    $cert = Resolve-Certificate
    Export-PublicCert $cert
    if ($Trust) { Install-Trust $cert }
    exit 0
}

if ($Sign) {
    Write-Head '签名'
    if (-not (Test-Path -LiteralPath $FilePath)) { Write-Host ('[FAIL] 文件不存在: ' + $FilePath); exit 2 }
    $cert = Resolve-Certificate
    Write-Host ('使用证书: ' + $cert.Subject + '  指纹=' + $cert.Thumbprint)
    $stoppedResident = Stop-ResidentIfNeeded
    $sig = Set-AuthenticodeSignature -FilePath $FilePath -Certificate $cert -HashAlgorithm SHA256
    if (-not $sig.SignerCertificate) {
        Write-Host ('[FAIL] 签名失败: ' + $sig.StatusMessage)
        if ($stoppedResident) { Start-ResidentIfNeeded }
        exit 2
    }
    if (-not $sig.SignerCertificate) { Write-Host ('[FAIL] 签名失败: ' + $sig.StatusMessage); exit 2 }
    Export-PublicCert $cert
    if ($Trust) { Install-Trust $cert }
    Write-Head '签名后校验'
    $ok = Test-Signature -path $FilePath -expectedThumb $cert.Thumbprint
    if ($stoppedResident) { Start-ResidentIfNeeded }
    if ($ok) { exit 0 }
    exit 2
}

Write-Head '校验'
if (Test-Signature -path $FilePath -expectedThumb $Thumbprint) { exit 0 }
exit 2
