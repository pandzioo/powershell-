<#
.SYNOPSIS
    Skrypt do weryfikacji statusu MFA (Multi-Factor Authentication) w środowisku Microsoft 365

.DESCRIPTION
    Ten skrypt łączy się z Microsoft 365 i sprawdza, które konta użytkowników mają włączone MFA,
    a które nie. Wyniki są eksportowane do pliku CSV i wyświetlane w konsoli.

.NOTES
    Autor: PowerShell MFA Verification Script
    Wymagania:
    - Moduł MSOnline lub Microsoft.Graph
    - Uprawnienia administratora Global Admin lub User Administrator w M365

.EXAMPLE
    .\Verify-M365MFAStatus.ps1
#>

# Parametry konfiguracyjne
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\MFA_Status_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [Parameter(Mandatory=$false)]
    [switch]$UseGraphAPI
)

# Funkcja do sprawdzania i instalacji wymaganych modułów
function Install-RequiredModules {
    param(
        [string]$ModuleName
    )

    Write-Host "Sprawdzanie modułu $ModuleName..." -ForegroundColor Cyan

    if (!(Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "Moduł $ModuleName nie jest zainstalowany. Rozpoczynam instalację..." -ForegroundColor Yellow
        try {
            Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
            Write-Host "Moduł $ModuleName został zainstalowany pomyślnie." -ForegroundColor Green
        }
        catch {
            Write-Error "Nie udało się zainstalować modułu $ModuleName. Błąd: $_"
            return $false
        }
    }
    else {
        Write-Host "Moduł $ModuleName jest już zainstalowany." -ForegroundColor Green
    }

    return $true
}

# Funkcja do weryfikacji MFA używając MSOnline
function Get-MFAStatusMSOnline {
    Write-Host "`nŁączenie z Microsoft 365 (MSOnline)..." -ForegroundColor Cyan

    try {
        Connect-MsolService -ErrorAction Stop
        Write-Host "Połączono pomyślnie!" -ForegroundColor Green
    }
    catch {
        Write-Error "Nie udało się połączyć z Microsoft 365. Błąd: $_"
        return $null
    }

    Write-Host "`nPobieranie listy użytkowników i sprawdzanie statusu MFA..." -ForegroundColor Cyan

    try {
        $users = Get-MsolUser -All | Where-Object { $_.UserType -eq "Member" }
        $results = @()
        $totalUsers = $users.Count
        $currentUser = 0

        foreach ($user in $users) {
            $currentUser++
            Write-Progress -Activity "Sprawdzanie statusu MFA" -Status "Przetwarzanie użytkownika $currentUser z $totalUsers" -PercentComplete (($currentUser / $totalUsers) * 100)

            $mfaStatus = "Wyłączone"
            $mfaMethods = @()
            $defaultMethod = "Brak"

            if ($user.StrongAuthenticationRequirements.State) {
                $mfaStatus = $user.StrongAuthenticationRequirements.State
            }

            if ($user.StrongAuthenticationMethods) {
                $mfaMethods = $user.StrongAuthenticationMethods | ForEach-Object { $_.MethodType }
                $defaultMethod = ($user.StrongAuthenticationMethods | Where-Object { $_.IsDefault -eq $true }).MethodType
                if (-not $defaultMethod) { $defaultMethod = "Nie ustawiono" }
            }

            $userInfo = [PSCustomObject]@{
                'Nazwa użytkownika' = $user.DisplayName
                'Email' = $user.UserPrincipalName
                'Status MFA' = $mfaStatus
                'Metody MFA' = ($mfaMethods -join ', ')
                'Domyślna metoda' = $defaultMethod
                'Konto włączone' = $user.BlockCredential -eq $false
                'Licencja' = $user.IsLicensed
                'Data utworzenia' = $user.WhenCreated
            }

            $results += $userInfo
        }

        Write-Progress -Activity "Sprawdzanie statusu MFA" -Completed
        return $results
    }
    catch {
        Write-Error "Błąd podczas pobierania danych użytkowników: $_"
        return $null
    }
}

# Funkcja do weryfikacji MFA używając Microsoft Graph API
function Get-MFAStatusGraphAPI {
    Write-Host "`nŁączenie z Microsoft Graph..." -ForegroundColor Cyan

    try {
        Connect-MgGraph -Scopes "User.Read.All", "UserAuthenticationMethod.Read.All", "AuditLog.Read.All" -ErrorAction Stop
        Write-Host "Połączono pomyślnie!" -ForegroundColor Green
    }
    catch {
        Write-Error "Nie udało się połączyć z Microsoft Graph. Błąd: $_"
        return $null
    }

    Write-Host "`nPobieranie listy użytkowników i sprawdzanie statusu MFA..." -ForegroundColor Cyan

    try {
        $users = Get-MgUser -All -Property DisplayName, UserPrincipalName, Id, CreatedDateTime, AccountEnabled
        $results = @()
        $totalUsers = $users.Count
        $currentUser = 0

        foreach ($user in $users) {
            $currentUser++
            Write-Progress -Activity "Sprawdzanie statusu MFA" -Status "Przetwarzanie użytkownika $currentUser z $totalUsers" -PercentComplete (($currentUser / $totalUsers) * 100)

            try {
                $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue

                $mfaMethods = @()
                $hasMFA = $false

                foreach ($method in $authMethods) {
                    $methodType = $method.AdditionalProperties.'@odata.type'
                    switch ($methodType) {
                        '#microsoft.graph.phoneAuthenticationMethod' {
                            $mfaMethods += "Telefon"
                            $hasMFA = $true
                        }
                        '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' {
                            $mfaMethods += "Microsoft Authenticator"
                            $hasMFA = $true
                        }
                        '#microsoft.graph.fido2AuthenticationMethod' {
                            $mfaMethods += "FIDO2"
                            $hasMFA = $true
                        }
                        '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' {
                            $mfaMethods += "Windows Hello"
                            $hasMFA = $true
                        }
                        '#microsoft.graph.emailAuthenticationMethod' {
                            $mfaMethods += "Email"
                        }
                        '#microsoft.graph.passwordAuthenticationMethod' {
                            # Ignorujemy hasło jako metodę MFA
                        }
                        '#microsoft.graph.softwareOathAuthenticationMethod' {
                            $mfaMethods += "Software Token"
                            $hasMFA = $true
                        }
                    }
                }

                $userInfo = [PSCustomObject]@{
                    'Nazwa użytkownika' = $user.DisplayName
                    'Email' = $user.UserPrincipalName
                    'Status MFA' = if ($hasMFA) { "Włączone" } else { "Wyłączone" }
                    'Metody MFA' = if ($mfaMethods.Count -gt 0) { ($mfaMethods -join ', ') } else { "Brak" }
                    'Liczba metod' = $mfaMethods.Count
                    'Konto włączone' = $user.AccountEnabled
                    'Data utworzenia' = $user.CreatedDateTime
                }

                $results += $userInfo
            }
            catch {
                Write-Warning "Nie można pobrać metod uwierzytelniania dla użytkownika: $($user.UserPrincipalName)"
            }
        }

        Write-Progress -Activity "Sprawdzanie statusu MFA" -Completed
        return $results
    }
    catch {
        Write-Error "Błąd podczas pobierania danych użytkowników: $_"
        return $null
    }
}

# Funkcja do generowania podsumowania
function Show-MFASummary {
    param(
        [array]$Results
    )

    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
    Write-Host "PODSUMOWANIE STATUSU MFA W ŚRODOWISKU M365" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan

    $totalUsers = $Results.Count
    $mfaEnabled = ($Results | Where-Object { $_.'Status MFA' -match 'Enforced|Enabled|Włączone' }).Count
    $mfaDisabled = $totalUsers - $mfaEnabled
    $percentEnabled = if ($totalUsers -gt 0) { [math]::Round(($mfaEnabled / $totalUsers) * 100, 2) } else { 0 }

    Write-Host "`nStatystyki ogólne:" -ForegroundColor Yellow
    Write-Host "  Łączna liczba użytkowników: $totalUsers"
    Write-Host "  Użytkownicy z MFA włączonym: $mfaEnabled ($percentEnabled%)" -ForegroundColor Green
    Write-Host "  Użytkownicy bez MFA: $mfaDisabled ($([math]::Round(100 - $percentEnabled, 2))%)" -ForegroundColor Red

    Write-Host "`nUżytkownicy BEZ włączonego MFA:" -ForegroundColor Red
    $noMFA = $Results | Where-Object { $_.'Status MFA' -notmatch 'Enforced|Enabled|Włączone' }
    if ($noMFA.Count -gt 0) {
        $noMFA | Format-Table 'Nazwa użytkownika', 'Email', 'Konto włączone' -AutoSize | Out-String | Write-Host
    }
    else {
        Write-Host "  Wszyscy użytkownicy mają włączone MFA! ✓" -ForegroundColor Green
    }

    Write-Host ("=" * 80) -ForegroundColor Cyan
}

# Główna logika skryptu
Clear-Host
Write-Host @"
╔════════════════════════════════════════════════════════════════════════════╗
║                 WERYFIKACJA STATUSU MFA W MICROSOFT 365                     ║
╚════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Wybór metody połączenia
if ($UseGraphAPI) {
    Write-Host "`nWybrano metodę: Microsoft Graph API" -ForegroundColor Yellow

    if (!(Install-RequiredModules -ModuleName "Microsoft.Graph.Authentication")) {
        exit 1
    }
    if (!(Install-RequiredModules -ModuleName "Microsoft.Graph.Users")) {
        exit 1
    }

    $results = Get-MFAStatusGraphAPI
}
else {
    Write-Host "`nWybrano metodę: MSOnline (domyślna)" -ForegroundColor Yellow
    Write-Host "Aby użyć Microsoft Graph API, uruchom skrypt z parametrem -UseGraphAPI" -ForegroundColor Gray

    if (!(Install-RequiredModules -ModuleName "MSOnline")) {
        exit 1
    }

    $results = Get-MFAStatusMSOnline
}

# Przetwarzanie wyników
if ($results -and $results.Count -gt 0) {
    # Export do CSV
    try {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "`n✓ Raport został zapisany do pliku: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Nie udało się zapisać raportu do pliku: $_"
    }

    # Wyświetlenie podsumowania
    Show-MFASummary -Results $results

    # Opcjonalne wyświetlenie pełnej listy
    Write-Host "`nCzy chcesz wyświetlić pełną listę wszystkich użytkowników? (T/N): " -ForegroundColor Yellow -NoNewline
    $response = Read-Host
    if ($response -match '^[TtYy]') {
        $results | Format-Table -AutoSize
    }
}
else {
    Write-Error "Nie udało się pobrać danych użytkowników lub lista jest pusta."
    exit 1
}

Write-Host "`n✓ Skrypt zakończył działanie." -ForegroundColor Green
