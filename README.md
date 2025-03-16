GraphiDev Bilişim - PowerShell ve PATH Düzeltme Aracı
Bu script, Windows sisteminde PowerShell ortamını ve PATH değişkenini düzeltir.
    - Eksik sistem dizinlerini PATH'e ekler
    - PowerShell'i en son sürüme günceller
    - WinGet'i kontrol eder ve gerekirse yüklenmesine yardımcı olur
    - PowerShell profilini düzenler
Yönetici olarak çalıştırılmalıdır.
Çalıştırmak için:
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
.\Fix-PowerShellEnvironment.ps1
