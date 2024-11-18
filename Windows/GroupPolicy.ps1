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