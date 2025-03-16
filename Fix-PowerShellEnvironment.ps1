<#
.SYNOPSIS
    GraphiDev Bilişim - PowerShell ve PATH Düzeltme Aracı
.DESCRIPTION
    Bu script, Windows sisteminde PowerShell ortamını ve PATH değişkenini düzeltir.
    - Eksik sistem dizinlerini PATH'e ekler
    - PowerShell'i en son sürüme günceller
    - WinGet'i kontrol eder ve gerekirse yüklenmesine yardımcı olur
    - PowerShell profilini düzenler
.NOTES
    Yönetici olarak çalıştırılmalıdır.
#>

# Yönetici kontrolü
function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $user
    $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "Bu script yönetici hakları gerektiriyor. Lütfen PowerShell'i yönetici olarak çalıştırın." -ForegroundColor Red
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Renkli başlık fonksiyonu
function Write-ColoredTitle {
    param([string]$Title)
    Write-Host "`n============================================" -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
}

# Ana menü
function Show-Menu {
    Clear-Host
    Write-Host "╔══════════════════════════════════════════════╗" -ForegroundColor Blue
    Write-Host "║       PowerShell ve PATH Düzeltme Aracı      ║" -ForegroundColor Blue
    Write-Host "╚══════════════════════════════════════════════╝" -ForegroundColor Blue
    Write-Host
    Write-Host " [1] PATH Değişkenini Düzelt" -ForegroundColor Green
    Write-Host " [2] PowerShell'i Güncelle" -ForegroundColor Green
    Write-Host " [3] WinGet'i Kur/Düzelt" -ForegroundColor Green
    Write-Host " [4] PowerShell Profilini Düzelt" -ForegroundColor Green
    Write-Host " [5] Tümünü Otomatik Düzelt" -ForegroundColor Yellow
    Write-Host " [6] Sistem Durumunu Kontrol Et" -ForegroundColor Cyan
    Write-Host " [Q] Çıkış" -ForegroundColor Red
    Write-Host
    Write-Host "Seçiminiz: " -NoNewline -ForegroundColor White
}

# PATH değişkenini düzeltme
function Fix-PathVariable {
    Write-ColoredTitle "PATH Değişkeni Düzeltiliyor"
    
    # Eklenecek önemli sistem dizinleri
    $essentialPaths = @(
        "C:\Windows",
        "C:\Windows\System32",
        "C:\Windows\System32\Wbem",
        "C:\Windows\System32\WindowsPowerShell\v1.0"
    )
    
    # Mevcut sistem PATH değişkenini al
    $systemPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    $systemPathArray = $systemPath -split ";"
    $pathUpdated = $false
    
    # Eksik dizinleri ekle
    foreach ($path in $essentialPaths) {
        if ($systemPathArray -notcontains $path) {
            $systemPath = "$path;$systemPath"
            $pathUpdated = $true
            Write-Host "Sistem PATH'ine eklendi: $path" -ForegroundColor Green
        }
    }
    
    if ($pathUpdated) {
        [Environment]::SetEnvironmentVariable("PATH", $systemPath, "Machine")
        Write-Host "Sistem PATH değişkeni güncellendi." -ForegroundColor Green
    } else {
        Write-Host "Sistem PATH değişkeninde eksik dizin bulunamadı." -ForegroundColor Yellow
    }
    
    # Mevcut oturum için PATH'i güncelle
    $env:PATH = [Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [Environment]::GetEnvironmentVariable("PATH", "User")
    
    Write-Host "PATH değişkeni düzeltme işlemi tamamlandı." -ForegroundColor Green
    Write-Host "Değişikliklerin tam olarak uygulanması için oturumu yeniden başlatmanız gerekebilir." -ForegroundColor Yellow
    Pause
}

# PowerShell'i güncelleme
function Update-PowerShell {
    Write-ColoredTitle "PowerShell Güncelleniyor"
    
    # Mevcut sürümü kontrol et
    $currentVersion = $PSVersionTable.PSVersion
    Write-Host "Mevcut PowerShell sürümü: $currentVersion" -ForegroundColor Cyan
    
    # En son sürümü kontrol et
    try {
        $latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
        $latestVersion = $latestRelease.tag_name.Substring(1) # "v7.5.0" -> "7.5.0"
        Write-Host "En son PowerShell sürümü: $latestVersion" -ForegroundColor Cyan
        
        if ([version]$currentVersion -ge [version]$latestVersion) {
            Write-Host "PowerShell zaten güncel." -ForegroundColor Green
            Pause
            return
        }
    } catch {
        Write-Host "En son sürüm bilgisi alınamadı. Varsayılan olarak 7.5.0 sürümüne güncelleniyor." -ForegroundColor Yellow
        $latestVersion = "7.5.0"
    }
    
    # Kullanıcıya sor
    $confirmation = Read-Host "PowerShell'i $latestVersion sürümüne güncellemek istiyor musunuz? (E/H)"
    if ($confirmation -ne "E" -and $confirmation -ne "e") {
        Write-Host "Güncelleme iptal edildi." -ForegroundColor Yellow
        Pause
        return
    }
    
    # İndirme ve yükleme
    try {
        $downloadUrl = "https://github.com/PowerShell/PowerShell/releases/download/v$latestVersion/PowerShell-$latestVersion-win-x64.msi"
        $installerPath = "$env:TEMP\PowerShell-$latestVersion-win-x64.msi"
        
        Write-Host "PowerShell $latestVersion indiriliyor..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath
        
        Write-Host "PowerShell $latestVersion yükleniyor..." -ForegroundColor Cyan
        $arguments = "/i `"$installerPath`" /quiet ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1 ADD_PATH=1"
        Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait
        
        Write-Host "PowerShell $latestVersion başarıyla yüklendi." -ForegroundColor Green
        Write-Host "Değişikliklerin tam olarak uygulanması için sistemi yeniden başlatmanız önerilir." -ForegroundColor Yellow
    } catch {
        Write-Host "PowerShell güncellemesi sırasında bir hata oluştu: $_" -ForegroundColor Red
    }
    
    Pause
}

# WinGet'i kurma/düzeltme
function Fix-WinGet {
    Write-ColoredTitle "WinGet Kontrol Ediliyor ve Düzeltiliyor"
    
    # WinGet'in yüklü olup olmadığını kontrol et
    $appInstallerPackage = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue
    
    if ($appInstallerPackage) {
        Write-Host "App Installer (WinGet) yüklü. Sürüm: $($appInstallerPackage.Version)" -ForegroundColor Green
        
        # WinGet'in çalışıp çalışmadığını kontrol et
        try {
            $wingetPath = Join-Path -Path $appInstallerPackage.InstallLocation -ChildPath "winget.exe"
            if (-not (Test-Path $wingetPath)) {
                $wingetPath = Join-Path -Path $appInstallerPackage.InstallLocation -ChildPath "AppInstallerCLI.exe"
            }
            
            if (Test-Path $wingetPath) {
                Write-Host "WinGet yolu: $wingetPath" -ForegroundColor Green
                
                # WindowsApps dizinini PATH'e ekle
                $windowsAppsPath = Split-Path -Parent $wingetPath
                if ($env:PATH -notlike "*$windowsAppsPath*") {
                    $env:PATH = "$env:PATH;$windowsAppsPath"
                    Write-Host "WindowsApps dizini geçici olarak PATH'e eklendi" -ForegroundColor Green
                }
                
                # WinGet'i test et
                & $wingetPath --version
                Write-Host "WinGet başarıyla çalıştırıldı." -ForegroundColor Green
            } else {
                Write-Host "WinGet yürütülebilir dosyası bulunamadı." -ForegroundColor Red
                throw "WinGet yürütülebilir dosyası bulunamadı."
            }
        } catch {
            Write-Host "WinGet çalıştırılamadı. Microsoft Store'dan yeniden yüklemeniz önerilir." -ForegroundColor Red
            $reinstall = Read-Host "App Installer'ı Microsoft Store'dan yeniden yüklemek istiyor musunuz? (E/H)"
            if ($reinstall -eq "E" -or $reinstall -eq "e") {
                Start-Process "ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1"
            }
        }
    } else {
        Write-Host "App Installer (WinGet) yüklü değil." -ForegroundColor Red
        $install = Read-Host "App Installer'ı Microsoft Store'dan yüklemek istiyor musunuz? (E/H)"
        if ($install -eq "E" -or $install -eq "e") {
            Start-Process "ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1"
        }
    }
    
    Pause
}

# PowerShell profilini düzeltme
function Fix-PowerShellProfile {
    Write-ColoredTitle "PowerShell Profili Düzeltiliyor"
    
    # Profil dizinini kontrol et
    $profileDir = Split-Path -Parent $PROFILE
    if (-not (Test-Path $profileDir)) {
        New-Item -Path $profileDir -ItemType Directory -Force
        Write-Host "PowerShell profil dizini oluşturuldu: $profileDir" -ForegroundColor Green
    }
    
    # Profil içeriği
    $profileContent = @'
# PATH değişkenini kontrol et ve gerekirse düzelt
$essentialPaths = @(
    "C:\Windows",
    "C:\Windows\System32",
    "C:\Windows\System32\Wbem",
    "C:\Windows\System32\WindowsPowerShell\v1.0"
)

foreach ($path in $essentialPaths) {
    if ($env:PATH -notlike "*$path*") {
        $env:PATH = "$path;$env:PATH"
    }
}

# WinGet modülünü koşullu olarak yükle
try {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Import-Module -Name Microsoft.WinGet.CommandNotFound -ErrorAction Stop
        Write-Host "WinGet komut bulunamadı modülü yüklendi" -ForegroundColor Green
    }
} catch {
    # Sessizce devam et
}

# Kullanışlı alias tanımlamaları
Set-Alias -Name np -Value notepad
Set-Alias -Name ll -Value Get-ChildItem

# Renkli prompt
function prompt {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal] $identity
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator

    $prefix = if ($principal.IsInRole($adminRole)) { "[ADMIN] " } else { "" }
    $path = $ExecutionContext.SessionState.Path.CurrentLocation.Path
    $userPrompt = "PS $prefix$path> "
    
    Write-Host $userPrompt -NoNewline -ForegroundColor Cyan
    return " "
}
'@
    
    # Profil dosyasını oluştur/güncelle
    Set-Content -Path $PROFILE -Value $profileContent -Force
    Write-Host "PowerShell profil dosyası güncellendi: $PROFILE" -ForegroundColor Green
    
    # Profili yeniden yükle
    try {
        . $PROFILE
        Write-Host "PowerShell profili başarıyla yüklendi." -ForegroundColor Green
    } catch {
        Write-Host "PowerShell profili yüklenirken hata oluştu: $_" -ForegroundColor Red
    }
    
    Pause
}

# Sistem durumunu kontrol etme
function Check-SystemStatus {
    Write-ColoredTitle "Sistem Durumu Kontrol Ediliyor"
    
    # PowerShell sürümü
    Write-Host "PowerShell Sürümü:" -ForegroundColor Cyan
    $PSVersionTable.PSVersion
    Write-Host
    
    # PATH değişkeni
    Write-Host "PATH Değişkeni:" -ForegroundColor Cyan
    $env:PATH -split ";" | ForEach-Object { Write-Host "  $_" }
    Write-Host
    
    # Önemli komutların durumu
    Write-Host "Önemli Komutların Durumu:" -ForegroundColor Cyan
    $commands = @("notepad", "winget", "pwsh")
    foreach ($cmd in $commands) {
        $cmdPath = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($cmdPath) {
            Write-Host "  $cmd : Çalışıyor - $($cmdPath.Source)" -ForegroundColor Green
        } else {
            Write-Host "  $cmd : Çalışmıyor" -ForegroundColor Red
        }
    }
    Write-Host
    
    # WinGet durumu
    Write-Host "WinGet Durumu:" -ForegroundColor Cyan
    try {
        $wingetVersion = winget --version 2>&1
        Write-Host "  WinGet Sürümü: $wingetVersion" -ForegroundColor Green
    } catch {
        Write-Host "  WinGet çalıştırılamadı" -ForegroundColor Red
    }
    Write-Host
    
    # PowerShell profili
    Write-Host "PowerShell Profili:" -ForegroundColor Cyan
    if (Test-Path $PROFILE) {
        Write-Host "  Profil dosyası mevcut: $PROFILE" -ForegroundColor Green
    } else {
        Write-Host "  Profil dosyası bulunamadı: $PROFILE" -ForegroundColor Red
    }
    
    Pause
}

# Tümünü otomatik düzelt
function Fix-All {
    Write-ColoredTitle "Tüm Düzeltmeler Uygulanıyor"
    
    Fix-PathVariable
    Update-PowerShell
    Fix-WinGet
    Fix-PowerShellProfile
    
    Write-Host "Tüm düzeltmeler tamamlandı." -ForegroundColor Green
    Write-Host "Değişikliklerin tam olarak uygulanması için sistemi yeniden başlatmanız önerilir." -ForegroundColor Yellow
    
    Pause
}

# Ana döngü
do {
    Show-Menu
    $selection = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character.ToString().ToUpper()
    
    switch ($selection) {
        "1" { Fix-PathVariable }
        "2" { Update-PowerShell }
        "3" { Fix-WinGet }
        "4" { Fix-PowerShellProfile }
        "5" { Fix-All }
        "6" { Check-SystemStatus }
        "Q" { return }
        default { Write-Host "`nGeçersiz seçim. Lütfen tekrar deneyin." -ForegroundColor Red; Pause }
    }
} while ($selection -ne "Q")