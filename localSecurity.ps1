# Download security template, and import the local template
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/moonmantee/CyberpatriotScript/main/Server2022SecPolTemplate.inf' -OutFile 'C:\template.inf'
secedit /import /db C:\Windows\security\database\secedit.sdb /cfg C:\template.inf

# Firewall Stuff:
# Enable Firewall
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
# Block all inbound connections for all profiles (Domain, Private, Public)
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block
# Allow all outbound connections for all profiles (Domain, Private, Public)
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow
# Set the Windows Firewall notification setting for Domain profile to 'No'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainFirewall\FirewallPolicies\{GUID}" -Name "EnableNotifications" -Value 0
# Define the logging path for Windows Firewall Domain profile
$logFilePath = "$env:SYSTEMROOT\System32\logfiles\firewall\domainfw.log"
# Enable logging for Domain profile
Set-NetFirewallProfile -Profile Domain -LogFileName $logFilePath -LogMaxSizeKilobytes 4096 -LogAllowed True -LogBlocked True
# Set the maximum log file size limit for the Domain profile to 8 MB (8192 KB)
$maxLogSizeKB = 16384  # 16 MB
# Configure the Domain profile's logging settings
Set-NetFirewallProfile -Profile Domain -LogMaxSizeKilobytes $maxLogSizeKB
# Start logging for dropped packets
Set-NetFirewallProfile -Profile Domain -Log