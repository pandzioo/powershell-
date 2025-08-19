<#+
.SYNOPSIS
    Adds users from a CSV file to the local Active Directory.
.DESCRIPTION
    Imports user records from a CSV file and creates new Active Directory user accounts.
    The CSV must provide the following columns:
        Name, GivenName, Surname, SamAccountName, UserPrincipalName, Path, Password
.EXAMPLE
    ./Add-ADUsers.ps1 -CsvPath ./users.csv
#>

param(
    [Parameter(Mandatory)]
    [string]$CsvPath
)

Import-Module ActiveDirectory

$users = Import-Csv -Path $CsvPath

foreach ($user in $users) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($user.SamAccountName)'")) {
        $securePassword = ConvertTo-SecureString $user.Password -AsPlainText -Force
        New-ADUser -Name $user.Name `
            -GivenName $user.GivenName `
            -Surname $user.Surname `
            -SamAccountName $user.SamAccountName `
            -UserPrincipalName $user.UserPrincipalName `
            -Path $user.Path `
            -AccountPassword $securePassword `
            -Enabled $true
        Write-Host "Created user $($user.SamAccountName)"
    }
    else {
        Write-Host "User $($user.SamAccountName) already exists."
    }
}
