# Define the list of registry paths and their corresponding REG_DWORD and REG_SZ settings
$registrySettings = @(
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Personalization"; Name = "PreventLockScreenCamera"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Personalization"; Name = "PreventLockScreenSlideShow"; Value = 1; Type = "DWORD" }

    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\RegionalSettings"; Name = "HandwritingPersonalization"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\RegionalSettings"; Name = "AllowOnlineSpeechRecognition"; Value = 0; Type = "DWORD" }

    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Personalization"; Name = "AllowOnlineTips"; Value = 0; Type = "DWORD" }

    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Desktop"; Name = "DesktopSetting"; Value = 1; Type = "DWORD" }

    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\LAPS"; Name = "LapsSetting"; Value = 1; Type = "DWORD" }

    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityGuide"; Name = "RpcPacketPrivacy"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityGuide"; Name = "SMBv1ClientDriver"; Value = 0x2; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityGuide"; Name = "SMBv1Server"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityGuide"; Name = "EnableCertificatePadding"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityGuide"; Name = "SEHOPEnabled"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityGuide"; Name = "LSAProtection"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityGuide"; Name = "NetBTNodeType"; Value = 0x2; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityGuide"; Name = "WDigestAuth"; Value = 0; Type = "DWORD" }

    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\MSS"; Name = "AutoAdminLogon"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\MSS"; Name = "DisableIPSourceRoutingIPv6"; Value = 0x3; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\MSS"; Name = "DisableIPSourceRouting"; Value = 0x3; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\MSS"; Name = "DisableSavePassword"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\MSS"; Name = "EnableICMPRedirect"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\MSS"; Name = "KeepAliveTime"; Value = 300000; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\MSS"; Name = "NoNameReleaseOnDemand"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\MSS"; Name = "PerformRouterDiscovery"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\MSS"; Name = "SafeDllSearchMode"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\MSS"; Name = "ScreenSaverGracePeriod"; Value = 5; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\MSS"; Name = "TcpMaxDataRetransmissionsIPv6"; Value = 3; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\MSS"; Name = "TcpMaxDataRetransmissions"; Value = 3; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\MSS"; Name = "WarningLevel"; Value = 90; Type = "DWORD" }

    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "BITSService"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "BranchCache"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "DirectAccessClientExperience"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "DNSClient"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "Fonts"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "EnableFontProviders"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "HotspotAuthentication"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "LanmanServer"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "LanmanWorkstation"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "EnableInsecureGuestLogons"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "LinkLayerTopologyDiscovery"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "MapperIODriver"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "ResponderDriver"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "PeerToPeerNetworking"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "ProhibitAccessWindowsConnectNow"; Value = 1; Type = "DWORD" }

    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "MinimizeSimultaneousConnections"; Value = 3; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "WLANMediaCost"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "WLANSettings"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"; Name = "AllowAutoConnectOpenHotspots"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler"; Name = "AllowClientConnections"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler"; Name = "ConfigureRedirectionGuard"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\RpcSs"; Name = "ProtocolForOutgoingRPCConnections"; Value = 1; Type = "DWORD" }  # 1 represents RPC over TCP
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\RpcSs"; Name = "UseAuthenticationForOutgoingRPCConnections"; Value = 1; Type = "DWORD" }  # Default value
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\RpcSs"; Name = "ProtocolsForIncomingRPCConnections"; Value = 1; Type = "DWORD" }  # 1 represents RPC over TCP
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\RpcSs"; Name = "AuthenticationProtocolForIncomingRPCConnections"; Value = 2; Type = "DWORD" }  # 2 represents Negotiate or higher
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\RpcSs"; Name = "RPCOverTCPPort"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler"; Name = "LimitPrintDriverInstallationToAdministrators"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler"; Name = "QueueSpecificFileProcessing"; Value = 1; Type = "DWORD" }  # 1 represents limiting to Color profiles
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler"; Name = "PointAndPrintWhenInstallingNewDrivers"; Value = 1; Type = "DWORD" }  # Show warning and elevation prompt
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler"; Name = "PointAndPrintWhenUpdatingExistingDrivers"; Value = 1; Type = "DWORD" }  # Show warning and elevation prompt
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications"; Name = "NoToastApplicationNotification"; Value = 1; Type = "DWORD" }
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications"; Name = "NoToastNetworkUsage"; Value = 1; Type = "DWORD" }

    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "IncludeCommandLineInProcessCreationEvents"; Value = 1; Type = "DWORD" }

    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EncryptionOracleRemediation"; Value = 1; Type = "DWORD" }  # 1 represents "Force Updated Clients"
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "AllowDelegationOfNonExportableCredentials"; Value = 1; Type = "DWORD" }

    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceGuard"; Name = "EnableVirtualizationBasedSecurity"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceGuard"; Name = "PlatformSecurityLevel"; Value = 2; Type = "DWORD" }  # 2 represents "Secure Boot" or higher
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceGuard"; Name = "VirtualizationBasedProtectionOfCodeIntegrity"; Value = 1; Type = "DWORD" }  # "Enabled with UEFI lock"
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceGuard"; Name = "RequireUEFIMemoryAttributesTable"; Value = 1; Type = "DWORD" }  # "True (checked)"
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceGuard"; Name = "CredentialGuardConfiguration"; Value = 1; Type = "DWORD" }  # "Enabled with UEFI lock"
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceGuard"; Name = "SecureLaunchConfiguration"; Value = 1; Type = "DWORD" }

    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "PreventDeviceMetadataRetrievalFromInternet"; Value = 1; Type = "DWORD" }

    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "AllowClipboardSynchronizationAcrossDevices"; Value = 0; Type = "DWORD" }
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "AllowUploadOfUserActivities"; Value = 0; Type = "DWORD" }

    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\TimeBroker"; Name = "EnableNtpClient"; Value = 1; Type = "DWORD" }

    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoInternetConnectionWizard"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStoreApp"; Value = 1; Type = "DWORD" }

    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ErrorReporting"; Name = "Disabled"; Value = 1; Type = "DWORD" }

    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\PerfTrack"; Name = "DisablePerfTrack"; Value = 1; Type = "DWORD" }

    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\TrustedPlatformModule"; Name = "EnableTpm"; Value = 1; Type = "DWORD" }

    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "AllowCustomSSPsAndAPsInLSASS"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "ConfiguresLSASSToRunAsProtectedProcess"; Value = 1; Type = "DWORD" }  # "Enabled with UEFI Lock"

    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "DisallowCopyingOfUserInputMethodsToSystemAccount"; Value = 1; Type = "DWORD" }

    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ShowAccountDetailsOnSignIn"; Value = 0; Type = "DWORD" }
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisplayNetworkSelectionUI"; Value = 0; Type = "DWORD" }
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "TurnOffAppNotificationsOnLockScreen"; Value = 1; Type = "DWORD" }
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ConveniencePINSignIn"; Value = 0; Type = "DWORD" }

    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\TimeBroker"; Name = "EnableWindowsNtpClient"; Value = 1; Type = "DWORD" }

    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "AllowStandbyStatesWhenSleeping"; Value = 0; Type = "DWORD" }  # S1-S3 Disabled
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "RequirePasswordWhenWaking"; Value = 1; Type = "DWORD" }  # Enabled on both battery and plugged-in states
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveX"; Name = "AllowActiveXInstall"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Upgrade"; Name = "EnableWindowsAnytimeUpgrade"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\AppDeployment"; Name = "AllowAppDataSharing"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\AppDeployment"; Name = "PreventNonAdminAppInstall"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\AppPrivacy"; Name = "ActivateVoiceAppWhenLocked"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\AppRuntime"; Name = "AllowMicrosoftAccountOptional"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\AppRuntime"; Name = "BlockUWAWithRuntimeAPI"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\AutoPlay"; Name = "DisallowAutoplayNonVolumeDevices"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\AutoPlay"; Name = "DisableAutoRun"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\AutoPlay"; Name = "TurnOffAutoplayAllDrives"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Biometrics"; Name = "EnableEnhancedAntiSpoofing"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "AllowAccessToBitLockerProtectedFixedDrives"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "AllowBitLockerRecoveryKey"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "AllowBitLockerRecoveryPassword"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "AllowBitLockerRecoveryAgent"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "AllowBitLockerOnOlderWindows"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "SaveBitLockerRecoveryInfoToAD"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "AllowBitLockerRecoveryWithoutTPM"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "AllowEnhancedPINForStartup"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "RequireAdditionalAuthenticationAtStartup"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "ConfigureStorageOfBitLockerRecoveryInfo"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "ConfigureHardwareBasedEncryptionForFixedDataDrives"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "ConfigureUseOfSmartCardsOnFixedDataDrives"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "RequireUseOfSmartCardsOnFixedDataDrives"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "AllowSecureBootForIntegrityValidation"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "RequirePasswordForFixedDataDrives"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "AllowBitLockerWithoutCompatibleTPM"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "ConfigureStorageOfBitLockerRecoveryInfoToADDS"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "ConfigureBitLockerRecoveryKey"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "EnableBitLockerOnOperatingSystemDrives"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "EnableRecoveryPasswordForOperatingSystemDrives"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "ConfigureBitLockerOperatingSystemDriveRecovery"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "ConfigureHardwareBasedEncryptionForOS"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "ConfigureSmartCardOnOS"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "ConfigureRecoveryPasswordForOS"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "EnableBitLockerWithoutCompatibleTPMForOS"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "RequireAdditionalAuthenticationForOS"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "AllowBitLockerWithRecoveryPassword"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "AllowAccessToBitLockerProtectedRemovableDrives"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "ChooseBitLockerRecoveryForRemovableDrives"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "AllowDataRecoveryAgentForRemovableDrives"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "AllowRecoveryPasswordForRemovableDrives"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "AllowRecoveryKeyForRemovableDrives"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "OmitRecoveryOptionsForRemovableDrives"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "SaveBitLockerRecoveryInfoToADDSForRemovableDrives"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "ConfigureBitLockerRecoveryInfoStorageToADDSForRemovableDrives"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "DoNotEnableBitLockerUntilRecoveryInfoIsStoredForRemovableDrives"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "ConfigureHardwareEncryptionForRemovableDataDrives"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "ConfigurePasswordForRemovableDataDrives"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "ConfigureSmartCardsForRemovableDataDrives"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "RequireSmartCardsForRemovableDataDrives"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "DenyWriteAccessToRemovableDrivesNotProtectedByBitLocker"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "DenyWriteAccessToUnprotectedRemovableDrivesInAnotherOrganization"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\BitLocker"; Name = "DisableNewDMADevicesWhenComputerIsLocked"; Value = 1; Type = "DWORD" }
# 18.10.10 Camera
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Camera"; Name = "AllowUseOfCamera"; Value = 0; Type = "DWORD" }

# 18.10.12 Cloud Content
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CloudContent"; Name = "TurnOffCloudConsumerAccountStateContent"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CloudContent"; Name = "TurnOffCloudOptimizedContent"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CloudContent"; Name = "TurnOffMicrosoftConsumerExperiences"; Value = 1; Type = "DWORD" }

# 18.10.13 Connect
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Connect"; Name = "RequirePinForPairing"; Value = 1; Type = "DWORD" }

# 18.10.14 Credential User Interface
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredentialUI"; Name = "DoNotDisplayPasswordRevealButton"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredentialUI"; Name = "EnumerateAdministratorAccountsOnElevation"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredentialUI"; Name = "PreventUseOfSecurityQuestionsForLocalAccounts"; Value = 1; Type = "DWORD" }

# 18.10.15 Data Collection and Preview Builds
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowDiagnosticData"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "ConfigureAuthenticatedProxyUsage"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "DisableOneSettingsDownloads"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "DoNotShowFeedbackNotifications"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "EnableOneSettingsAuditing"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "LimitDiagnosticLogCollection"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "LimitDumpCollection"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "ToggleUserControlOverInsiderBuilds"; Value = 0; Type = "DWORD" }

# 18.10.16 Delivery Optimization
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DeliveryOptimization"; Name = "DownloadMode"; Value = 0; Type = "DWORD" }

# 18.10.17 Desktop App Installer
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\AppInstaller"; Name = "EnableAppInstaller"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\AppInstaller"; Name = "EnableAppInstallerExperimentalFeatures"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\AppInstaller"; Name = "EnableAppInstallerHashOverride"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\AppInstaller"; Name = "EnableAppInstallerMsAppInstallerProtocol"; Value = 0; Type = "DWORD" }

# 18.10.28 File Explorer
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "TurnOffDataExecutionPreventionForExplorer"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "TurnOffHeapTerminationOnCorruption"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "TurnOffShellProtocolProtectedMode"; Value = 0; Type = "DWORD" }

# 18.10.34 Internet Explorer
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main"; Name = "DisableStandaloneBrowser"; Value = 1; Type = "DWORD" }

# 18.10.36 Location and Sensors
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LocationAndSensors"; Name = "TurnOffLocation"; Value = 1; Type = "DWORD" }

# 18.10.40 Messaging
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Messaging"; Name = "AllowMessageServiceCloudSync"; Value = 0; Type = "DWORD" }

# 18.10.41 Microsoft Account
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\MicrosoftAccount"; Name = "BlockAllConsumerMicrosoftAccountUserAuthentication"; Value = 1; Type = "DWORD" }

# 18.10.42 Microsoft Defender Antivirus
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Antivirus"; Name = "ConfigureLocalSettingOverrideForReportingToMicrosoftMAPS"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Antivirus"; Name = "JoinMicrosoftMAPS"; Value = 0; Type = "DWORD" }

# 18.10.42.6 Microsoft Defender Exploit Guard - Attack Surface Reduction
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\ExploitGuard\ASR"; Name = "ConfigureAttackSurfaceReductionRules"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\ExploitGuard\ASR"; Name = "SetStateForEachASRRule"; Value = 1; Type = "DWORD" }

# 18.10.42.6.3 Network Protection
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\ExploitGuard\NetworkProtection"; Name = "PreventUsersAndAppsFromAccessingDangerousWebsites"; Value = 1; Type = "DWORD" }

# 18.10.42.10 Real-time Protection
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-timeProtection"; Name = "ScanAllDownloadedFilesAndAttachments"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-timeProtection"; Name = "TurnOffRealTimeProtection"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-timeProtection"; Name = "TurnOnBehaviorMonitoring"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-timeProtection"; Name = "TurnOnScriptScanning"; Value = 1; Type = "DWORD" }

# 18.10.42.12 Reporting
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Reporting"; Name = "ConfigureWatsonEvents"; Value = 0; Type = "DWORD" }

# 18.10.42.13 Scan
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Scan"; Name = "ScanPackedExecutables"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Scan"; Name = "ScanRemovableDrives"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Scan"; Name = "TurnOnEmailScanning"; Value = 1; Type = "DWORD" }

# 18.10.42.16 Threats
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Threats"; Name = "ConfigureDetectionForPotentiallyUnwantedApplications"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Threats"; Name = "TurnOffMicrosoftDefenderAntiVirus"; Value = 0; Type = "DWORD" }

# 18.10.43 Microsoft Defender
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\MicrosoftDefenderAppGuard"; Name = "AllowAuditingEvents"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\MicrosoftDefenderAppGuard"; Name = "AllowCameraAndMicrophoneAccess"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\MicrosoftDefenderAppGuard"; Name = "AllowDataPersistence"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\MicrosoftDefenderAppGuard"; Name = "AllowFileDownloadAndSave"; Value = 0; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\MicrosoftDefenderAppGuard"; Name = "ClipboardBehaviorSetting"; Value = 1; Type = "DWORD" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\MicrosoftDefenderAppGuard"; Name = "EnableAppGuardManagedMode"; Value = 1; Type = "DWORD" }
# 18.10.49 News and Interests
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds"; Name = "ShellFeedsTaskbarViewMode"; Value = 0; Type = "DWORD" }  # Disable News and Interests on Taskbar

# 18.10.50 OneDrive (formerly SkyDrive)
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\OneDrive"; Name = "DisableFileSyncNGSC"; Value = 1; Type = "DWORD" }  # Prevent OneDrive file storage

# 18.10.55 Push To Install
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\PushToInstall"; Name = "EnablePushToInstall"; Value = 0; Type = "DWORD" }  # Disable Push to Install service

# 18.10.56 Remote Desktop Services (formerly Terminal Services)

## 18.10.56.2 Remote Desktop Connection Client
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "DisablePasswordSaving"; Value = 1; Type = "DWORD" }  # Disable saving passwords in Remote Desktop

# 18.10.56.3 Remote Desktop Session Host (formerly Terminal Server)

## 18.10.56.3.2 Connections
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "fDenyTSConnections"; Value = 1; Type = "DWORD" }  # Disable Remote Desktop Connections

## 18.10.56.3.3 Device and Resource Redirection
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "fDisableCdm"; Value = 1; Type = "DWORD" }  # Disable CD Redirection
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "fDisableComPort"; Value = 1; Type = "DWORD" }  # Disable COM Port Redirection
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "fDisableDriveRedirection"; Value = 1; Type = "DWORD" }  # Disable Drive Redirection
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "fDisableLptPortRedirection"; Value = 1; Type = "DWORD" }  # Disable LPT Port Redirection
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "fDisablePnPRedirection"; Value = 1; Type = "DWORD" }  # Disable Plug and Play Device Redirection
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "fDisableLocationRedirection"; Value = 1; Type = "DWORD" }  # Disable Location Redirection

## 18.10.56.3.9 Security
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "fPromptForPassword"; Value = 1; Type = "DWORD" }  # Prompt for password upon connection
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "RequireSecureRPC"; Value = 1; Type = "DWORD" }  # Require secure RPC communication
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "SecurityLayer"; Value = 2; Type = "DWORD" }  # Set security layer to SSL
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "UserAuthenticationRequired"; Value = 1; Type = "DWORD" }  # Require user authentication for Remote Desktop

## 18.10.56.3.10 Session Time Limits
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "MaxIdleTime"; Value = 900; Type = "DWORD" }  # Set idle session time limit to 15 minutes
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name = "MaxDisconnectionTime"; Value = 60; Type = "DWORD" }  # Set disconnected session time limit to 1 minute

## 18.10.56.3.11 Temporary folders
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "DeleteTempFilesUponExit"; Value = 0; Type = "DWORD" }  # Ensure temp folders are deleted upon exit

# 18.10.57 RSS Feeds
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"; Name = "DisableDownloadingOfEnclosures"; Value = 1; Type = "DWORD" }  # Prevent downloading of enclosures in RSS feeds

# 18.10.58 Search
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "AllowCloudSearch"; Value = 0; Type = "DWORD" }  # Disable cloud search
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "AllowCortana"; Value = 0; Type = "DWORD" }  # Disable Cortana
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "AllowSearchToUseLocation"; Value = 0; Type = "DWORD" }  # Disable search and Cortana from using location

# 18.10.62 Software Protection Platform
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\SPP"; Name = "DisableKMSClientOnlineValidation"; Value = 1; Type = "DWORD" }  # Turn off KMS Client Online AVS validation

# 18.10.63 Sound Recorder
# No specific registry settings to enforce for Sound Recorder

# 18.10.64 Speech
# No specific registry settings to enforce for Speech

# 18.10.65 Store
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Store"; Name = "DisableAllAppsFromStore"; Value = 1; Type = "DWORD" }  # Disable all apps from Microsoft Store
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Store"; Name = "OnlyDisplayPrivateStore"; Value = 1; Type = "DWORD" }  # Only display private store in Microsoft Store
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Store"; Name = "TurnOffAutoDownloadInstallUpdates"; Value = 1; Type = "DWORD" }  # Turn off automatic download and install of updates
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Store"; Name = "TurnOffUpdateOffer"; Value = 0; Type = "DWORD" }  # Turn off offer to update to latest version of Windows
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Store"; Name = "TurnOffStoreApp"; Value = 1; Type = "DWORD" }  # Turn off Store application
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="TaskbarDa";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="UseStartCalendar";Value=0;Type="DWORD"}
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";Name="ColorPrevalence";Value=0;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\SQMClient\Windows\Disabled";Name="CEIPEnable";Value=0;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen";Name="EnableSmartScreen";Value=0;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen";Name="EnhancedProtection";Value=0;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting";Name="Disabled";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR";Name="AppCaptureEnabled";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR";Name="GameDVR_Enabled";Value=0;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork";Name="Enabled";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace";Name="AllowSuggestedApps";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\InkWorkspace";Name="Enabled";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer";Name="DisableMSI";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer";Name="AllowUserControlOverInstalls";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer";Name="AlwaysInstallWithElevatedPrivileges";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer";Name="PreventInternetExplorerSecurityPromptForWindowsInstallerScripts";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\System";Name="EnableMPRNotifications";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\System";Name="SignInLastInteractiveUser";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows Media\Player";Name="PreventMediaPlayer";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Messenger";Name="EnableMessenger";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Desktop";Name="MobilePC";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell";Name="EnableScriptBlockLogging";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell";Name="EnableTranscription";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability";Name="Enable";Value=0;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service";Name="AllowBasicAuth";Value=0;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service";Name="AllowUnencrypted";Value=0;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service";Name="DisallowDigest";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox";Name="AllowClipboardSharing";Value=0;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox";Name="AllowNetworking";Value=0;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SecurityCenter";Name="DisableSecurityCenter";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SecurityCenter";Name="PreventUsersFromModifyingSettings";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";Name="NoAutoRebootWithLoggedOnUsers";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";Name="NoAutoRebootWithLoggedOnUsers";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";Name="ConfigureAutomaticUpdates";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";Name="ScheduledInstallDay";Value=0;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";Name="RemoveAccessToPauseUpdates";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";Name="ManagePreviewBuilds";Value=0;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";Name="SelectWhenPreviewBuildsAreReceived";Value=180;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";Name="SelectWhenFeatureUpdatesAreReceived";Value=180;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";Name="SelectWhenQualityUpdatesAreReceived";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications";Name="DoNotDisturb";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications";Name="ToastEnabled";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="ShowWindowsStoreApp";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="NoFileSharing";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="NoChangeStartMenu";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="DisableStartMenu";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="NoStartMenuPinnedList";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="StartMenuLayout";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="StartMenuHideShutdown";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="StartMenuDisableBackground";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="StartMenuShowAllPrograms";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="StartMenuDisableStartScreen";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="NoDesktop";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="NoChangeStartMenu";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="DisableControlPanel";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="NoSettings";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="NoNetwork";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="EnableDesktop";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="NoRemoteDesktop";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="DisableShutdown";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="DisableCtrlAltDel";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="NoTaskbar";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="NoStartMenu";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="TaskbarNoNotifications";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="DisableTaskbarOnLock";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="AutoPlay";Value=0;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="NoWindowsStore";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="NoAutoPlay";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="DisableSearch";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="NoInternet";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="DisableCalculator";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="DisableCloudContent";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="NoStartSearch";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="DisableLockScreen";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="DisableSpotlight";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="DisableSpotlight";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="Spotlight";Value=0;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="NoStartUpdates";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="NoTaskbarSearchBox";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="NoLockScreen";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="LockScreen";Value=0;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="NoOneDrive";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="NoOneDrive";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="DisableSharing";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="DisableLibraries";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="DisableOneDrive";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="DisableAppStore";Value=1;Type="DWORD"}
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";Name="DisableSearchBox";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="DisableDriverUpdates";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="DisableFolderRedirection";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="DisableWebClient";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="DisableTaskbar";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="DisableTaskbarSearch";Value=1;Type="DWORD"}
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";Name="DisableTaskbarWidgets";Value=1;Type="DWORD"}

)

foreach ($setting in $registrySettings) {
    # Extract the registry path, value name, value, and type from the current setting
    $registryPath = $setting.Path
    $valueName = $setting.Name
    $value = $setting.Value
    $type = $setting.Type

    # Check if the registry path exists
    if (-not (Test-Path $registryPath)) {
        # Create the registry path if it does not exist
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Set the registry value based on the type
    if ($type -eq "DWORD") {
        New-ItemProperty -Path $registryPath -Name $valueName -Value $value -PropertyType DWORD -Force | Out-Null
    } elseif ($type -eq "SZ") {
        New-ItemProperty -Path $registryPath -Name $valueName -Value $value -PropertyType String -Force | Out-Null
    }
}

Write-Output "All specified registry values have been updated."