# Check for admin privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Restart the script with admin privileges
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$response = Read-Host "Would you like to apply Group Policy? [y/n]"
if ($response -eq 'y' -or $response -eq 'Y') {
    Write-Host "Continuing..."
    & .\GroupPolicy.ps1
}

$response = Read-Host "Would you like to apply Local Security Policy? [y/n]"
if ($response -eq 'y' -or $response -eq 'Y') {
    Write-Host "Continuing..."
    & .\securityPolicy.ps1
}

$response = Read-Host "Would you like to apply Firewall Policies? [y/n]"
if ($response -eq 'y' -or $response -eq 'Y') {
    Write-Host "Continuing..."
    & .\firewall.ps1
}

$response = Read-Host "Would you like to apply Audit Policies? [y/n]"
if ($response -eq 'y' -or $response -eq 'Y') {
    Write-Host "Continuing..."
    & .\audit.ps1
}

$response = Read-Host "Would you like to disable Bad Services? [y/n]"
if ($response -eq 'y' -or $response -eq 'Y') {
    Write-Host "Continuing..."
    & .\services.ps1
}

$response = Read-Host "Would you like to delete media files [y/n]"
if ($response -eq 'y' -or $response -eq 'Y') {
    Write-Host "Continuing..."
    & .\media.ps1
}