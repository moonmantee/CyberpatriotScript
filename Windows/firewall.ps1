# Firewall Stuff:
# Configure Domain Profile
Set-NetFirewallProfile -Profile Domain -Enabled True
Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain -DefaultOutboundAction Allow
Set-NetFirewallProfile -Profile Domain -NotifyOnListen No
Set-NetFirewallProfile -Profile Domain -LogFileName "$env:systemroot\System32\logfiles\firewall\domainfw.log"
Set-NetFirewallProfile -Profile Domain -LogMaxSizeKB 16384
Set-NetFirewallProfile -Profile Domain -LogDroppedPackets Enabled
Set-NetFirewallProfile -Profile Domain -LogSuccessfulConnections Enabled

# Configure Private Profile
Set-NetFirewallProfile -Profile Private -Enabled True
Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Private -DefaultOutboundAction Allow
Set-NetFirewallProfile -Profile Private -NotifyOnListen No
Set-NetFirewallProfile -Profile Private -LogFileName "$env:systemroot\System32\logfiles\firewall\privatefw.log"
Set-NetFirewallProfile -Profile Private -LogMaxSizeKB 16384
Set-NetFirewallProfile -Profile Private -LogDroppedPackets Enabled
Set-NetFirewallProfile -Profile Private -LogSuccessfulConnections Enabled

# Configure Public Profile
Set-NetFirewallProfile -Profile Public -Enabled True
Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Public -DefaultOutboundAction Allow
Set-NetFirewallProfile -Profile Public -NotifyOnListen No
Set-NetFirewallProfile -Profile Public -ApplyLocalFirewallRules No
Set-NetFirewallProfile -Profile Public -ApplyLocalConnectionSecurityRules No
Set-NetFirewallProfile -Profile Public -LogFileName "$env:systemroot\System32\logfiles\firewall\publicfw.log"
Set-NetFirewallProfile -Profile Public -LogMaxSizeKB 16384
Set-NetFirewallProfile -Profile Public -LogDroppedPackets Enabled
Set-NetFirewallProfile -Profile Public -LogSuccessfulConnections Enabled

