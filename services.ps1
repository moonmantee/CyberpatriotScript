$servicesToDisable = @(
    "BthHFSrv",
    "bthserv",
    "Browser",
    "MapsBroker",
    "lfsv",
    "HomeGroupListener",
    "HomeGroupProvider",
    "IISADMIN",
    "irmon",
    "ICS",
    "lltdsvc",
    "LxssManager",
    "FTPSVC",
    "MSiSCSI",
    "PNRPsvc",
    "p2psvc",
    "p2pimsvc",
    "PNRPAutoReg",
    "wercplsupport",
    "RasAuto",
    "SessionEnv",
    "TermService",
    "UmRdpService",
    "RPC",
    "RpcLocator",
    "RemoteRegistry",
    "RemoteAccess",
    "LanmanServer",
    "simptcp",
    "SNMP",
    "SSDPSRV",
    "upnphost",
    "WMSvc",
    "WerSvc",
    "WMPNetworkSvc",
    "icssvc",
    "WpnService",
    "PushToInstall",
    "WinRM",
    "InstallService",
    "W3SVC",
    "XboxGipSvc",
    "xbgm",
    "XblAuthManager",   
    "XblGameSave",
    "XboxNetApiSvc"
)
$servicesToEnable = @(
    "wscsvc"
)

foreach($service in $servicesToDisable){
    Stop-Service -Name $service -ErrorAction SilentlyContinue
    Set-Service -Name $service -StartupType Disabled
}
foreach($service in $servicesToEnable){
    Set-Service -Name $service -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name $service -ErrorAction SilentlyContinue
}