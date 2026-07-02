<#
.SYNOPSIS
    اسکریپت پاک‌سازی و ریشه‌کنی ابزار نظارتی غیرمجاز (Net Monitor for Employees Pro)
    شناسه پردازش هدف: 5068 | پورت هدف: 4495
.DESCRIPTION
    این اسکریپت فرآیندهای مشکوک را متوقف کرده، سرویس‌های ویندوزی مرتبط را حذف،
    فایل‌های باینری را پاک‌سازی و پورت فایروال را مسدود می‌کند.
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] شروع عملیات پاک‌سازی و ریشه‌کنی تهدید..." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# ۱. متوقف کردن فرآیندهای مشکوک در حافظه
$ProcessNames = @("nmep_ctrlagent", "nmep_agent", "nmep_ctrlagentsvc")
foreach ($Proc in $ProcessNames) {
    if (Get-Process -Name $Proc -ErrorAction SilentlyContinue) {
        Write-Host "[!] فرآیند فعال یافت شد: $Proc. در حال متوقف کردن..." -ForegroundColor Yellow
        Stop-Process -Name $Proc -Force
        Write-Host "[+] فرآیند $Proc با موفقیت متوقف شد." -ForegroundColor Green
    }
}

# بررسی اختصاصی برای مطمئن شدن از خاتمه PID 5068
if (Get-Process -Id 5068 -ErrorAction SilentlyContinue) {
    Write-Host "[!] پردازش PID 5068 همچنان فعال است. توقف اجباری..." -ForegroundColor Yellow
    Stop-Process -Id 5068 -Force
}

# ۲. توقف و حذف سرویس‌های ویندوزی (از طریق ابزار SCM)
$ServiceNames = @("nlnme_ctrlagent", "nmep_ctrlagent", "nmep_agent", "NetMonitorEmployees")
foreach ($Svc in $ServiceNames) {
    if (Get-Service -Name $Svc -ErrorAction SilentlyContinue) {
        Write-Host "[!] سرویس یافت شد: $Svc. در حال توقف و حذف..." -ForegroundColor Yellow
        Stop-Service -Name $Svc -Force -ErrorAction SilentlyContinue
        sc.exe delete $Svc | Out-Null
        Write-Host "[+] سرویس با موفقیت حذف شد: $Svc" -ForegroundColor Green
    }
}

# ۳. پاک‌سازی و مسدودسازی پورت شبکه (4495)
Write-Host "[*] در حال بررسی و پاک‌سازی قوانین فایروال برای پورت 4495..." -ForegroundColor Cyan
$BadRules = Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*Net Monitor*" -or $_.DisplayName -like "*nmep*" -or $_.DisplayName -like "*nlnme*"}
if ($BadRules) {
    foreach ($Rule in $BadRules) {
        Remove-NetFirewallRule -Name $Rule.Name
        Write-Host "[+] قانون فایروال قدیمی حذف شد: $($Rule.DisplayName)" -ForegroundColor Green
    }
}

Write-Host "[*] ایجاد قانون مسدودسازی قطعی (Explicit Block) برای پورت 4495..." -ForegroundColor Cyan
New-NetFirewallRule -DisplayName "BLOCK_Unauthorized_4495_In" -Direction Inbound -LocalPort 4495 -Protocol TCP -Action Block | Out-Null
New-NetFirewallRule -DisplayName "BLOCK_Unauthorized_4495_Out" -Direction Outbound -LocalPort 4495 -Protocol TCP -Action Block | Out-Null
Write-Host "[+] پورت 4495 در هر دو جهت ورودی و خروجی مسدود شد." -ForegroundColor Green

# ۴. حذف فایل‌های باینری و پوشه‌های باقی‌مانده روی دیسک
$TargetPaths = @(
    "C:\Windows\SysWOW64\nlnme",
    "C:\Windows\System32\nlnme",
    "$env:ProgramFiles\nlnme",
    "$env:ProgramFiles (x86)\nlnme",
    "$env:ProgramData\nlnme"
)

foreach ($Path in $TargetPaths) {
    if (Test-Path $Path) {
        Write-Host "[!] پوشه باقی‌مانده روی دیسک یافت شد: $Path. در حال حذف..." -ForegroundColor Yellow
        Remove-Item -Path $Path -Recurse -Force
        Write-Host "[+] پوشه با موفقیت حذف شد: $Path" -ForegroundColor Green
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[+] عملیات ریشه‌کنی تهدید با موفقیت به پایان رسید!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
