function Disable-AccessibilityKeyPrompts {
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506" | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "58" | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "122" | Out-Null
}

function Disable-ActivityHistory {
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0 | Out-Null
}

function Disable-AdvertisingID {
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1 | Out-Null
}

function Disable-ApplicationSuggestionsAndAutomaticInstallation {
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 | Out-Null
	if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0 | Out-Null
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Type DWord -Value 0 | Out-Null
	# Empty placeholder tile collection in registry cache and restart Start Menu process to reload the cache
	if ([System.Environment]::OSVersion.Version.Build -ge 17134) {
		$key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*windows.data.placeholdertilecollection\Current"
		Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $key.Data[0..15] | Out-Null
		Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
	}
}

function Disable-AutomaticMapsUpdates {
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0 | Out-Null
}

function Disable-ErrorReporting {
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1 | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}

function Disable-NavPaneExpandToCurrentFolder {
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -ErrorAction SilentlyContinue | Out-Null
}

function Disable-ExplorerRecentFilesList {
	if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type DWord -Value 1 | Out-Null
}

function Disable-Feedback {
	if (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1 | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

function Disable-GameDVR {
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Type Dword -Value 2 | Out-Null
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type Dword -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type Dword -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type Dword -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_EFSEFeatureFlags" -Type Dword -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type Dword -Value 0 | Out-Null
}

function Disable-LocationTracking {
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type Dword -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type Dword -Value 0 | Out-Null
}

function Disable-NewContextMenu {
	New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Name "InprocServer32" -force -value ""
}

function Disable-OneDrive {
	Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	if (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait | Out-Null
	Start-Sleep -s 2
	Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	if ((Get-ChildItem -Path "$env:USERPROFILE\OneDrive" -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
		Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
	}
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
	if (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue | Out-Null
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue | Out-Null
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1 | Out-Null
}

function Disable-SearchBloat {
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0 | Out-Null
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value | Out-Null
}

function Disable-StorageSense {
	Remove-Item -Path \"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy\" -Recurse -ErrorAction SilentlyContinue | Out-Null
}

function Disable-TailoredExperiences {
	if (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1 | Out-Null
}

function Disable-Telemetry {
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 | Out-Null

	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Type DWord -Value 0 | Out-Null

	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Type DWord -Value 1 | Out-Null

	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0 | Out-Null

	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWord -Value 1 | Out-Null

	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Type DWord -Value 0 | Out-Null

	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1 | Out-Null

	if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Type DWord -Value 0 | Out-Null

	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1 | Out-Null

	if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1 | Out-Null

	if (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0 | Out-Null

	if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 1 | Out-Null

	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

	# Office 2016 / 2019
	Disable-ScheduledTask -TaskName "Microsoft\Office\Office ClickToRun Service Monitor" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentFallBack2016" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentLogOn2016" -ErrorAction SilentlyContinue | Out-Null
}

function Disable-UnknownExtensionAppSuggestion {
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1 | Out-Null
}

function Disable-WifiSense {
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0 | Out-Null
}

function Enable-LongFilePaths {
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Type DWord -Value 1 | Out-Null
}

function Hide-DesktopIcons {
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 1 | Out-Null
}

function Hide-ExplorerRecentFiles {
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0 | Out-Null
}

function Hide-StartMenuRecentlyAdded {
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1 | Out-Null
}

function Hide-TaskbarTaskView {
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0 | Out-Null
}

function Hide-TaskbarPeople {
	if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0 | Out-Null
}

function Hide-TaskbarSearch {
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0 | Out-Null
}

function Uninstall-Teams {
	$TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams')
	$TeamsUpdateExePath = [System.IO.Path]::Combine($TeamsPath, 'Update.exe')
	Stop-Process -Name "*teams*" -Force -ErrorAction SilentlyContinue

	if ([System.IO.File]::Exists($TeamsUpdateExePath)) {
		# Uninstall app
		$proc = Start-Process $TeamsUpdateExePath -uninstall -s -PassThru | Out-Null
		$proc.WaitForExit()
	}

	Get-AppxPackage "*Teams*" | Remove-AppxPackage -ErrorAction SilentlyContinue
	Get-AppxPackage "*Teams*" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

	if ([System.IO.Directory]::Exists($TeamsPath)) {
		Remove-Item $TeamsPath -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
	}

	# Uninstall from Uninstall registry key UninstallString
	$us = (Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | Get-ItemProperty | Where-Object { $_.DisplayName -like '*Teams*'}).UninstallString
	if ($us.Length -gt 0) {
		$us = ($us.Replace('I', 'uninstall') + 'quiet').Replace('', '')
		$FilePath = ($us.Substring(0, $us.IndexOf('.exe') + 4).Trim())
		$ProcessArgs = ($us.Substring($us.IndexOf('.exe') + 5).Trim().replace('', ''))
		$proc = Start-Process -FilePath $FilePath -Args $ProcessArgs -PassThru | Out-Null
		$proc.WaitForExit()
	}
}

function Show-AllTrayIcons {
	if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoTrayNotify" -Type DWord -Value 1 | Out-Null
}

function Enable-ExplorerFileExtensions {
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0 | Out-Null
}

function Optimize-Network {
	Set-NetTCPSetting -SettingName internet -AutoTuningLevelLocal disabled | Out-Null
	Set-NetTCPSetting -SettingName internet -ScalingHeuristics disabled | Out-Null
	netsh int tcp set supplemental internet congestionprovider=ctcp
	Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing disabled | Out-Null
	Set-NetOffloadGlobalSetting -ReceiveSideScaling disabled | Out-Null
	Disable-NetAdapterLso -Name * | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" -Name "explorer.exe" -Type DWord -Value 10 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" -Name "iexplore.exe" -Type DWord -Value 10 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" -Name "explorer.exe" -Type DWord -Value 10 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" -Name "iexplore.exe" -Type DWord -Value 10 | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "LocalPriority" -Type DWord -Value 4 | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "HostsPriority" -Type DWord -Value 5 | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "DnsPriority" -Type DWord -Value 6 | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "NetbtPriority" -Type DWord -Value 7 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" -Name "Do Not use NLA" -Type String -Value 1 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "AlwaysOn" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xffffffff | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NoLazyMode" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "Size" -Type DWord -Value 3 | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxUserPort" -Type DWord -Value 65534 | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpTimedWaitDelay" -Type DWord -Value 30 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" -Name "TCPNoDelay" -Type String -Value "" | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Type String -Value "" | Out-Null
	Set-NetTCPSetting -SettingName internet -EcnCapability disabled | Out-Null
	Set-NetOffloadGlobalSetting -Chimney disabled | Out-Null
	Set-NetTCPSetting -SettingName internet -Timestamps disabled | Out-Null
	Set-NetTCPSetting -SettingName internet -MaxSynRetransmissions 2 | Out-Null
	Set-NetTCPSetting -SettingName internet -NonSackRttResiliency disabled | Out-Null
	Set-NetTCPSetting -SettingName internet -InitialRtoMs 2000 | Out-Null
	Set-NetTCPSetting -SettingName internet -MinRtoMs 300 | Out-Null
	netsh interface ipv4 set subinterface "Ethernet 2" mtu=1492 store=persistent
	netsh interface ipv6 set subinterface "Ethernet 2" mtu=1492 store=persistent
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{faf0c941-8197-4a30-b959-e93cf2efaf9c}" -Name "TcpAckFrequency" -Type String -Value "" | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{faf0c941-8197-4a30-b959-e93cf2efaf9c}" -Name "TcpDelAckTicks" -Type String -Value "" | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{faf0c941-8197-4a30-b959-e93cf2efaf9c}" -Name "TCPNoDelay" -Type String -Value "" | Out-Null
	netsh interface ipv4 set subinterface "Ethernet" mtu=1492 store=persistent
	netsh interface ipv6 set subinterface "Ethernet" mtu=1492 store=persistent
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{eca522f4-2df2-4e86-a441-ebcec874e655}" -Name "TcpAckFrequency" -Type String -Value "" | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{eca522f4-2df2-4e86-a441-ebcec874e655}" -Name "TcpDelAckTicks" -Type String -Value "" | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{eca522f4-2df2-4e86-a441-ebcec874e655}" -Name "TCPNoDelay" -Type String -Value "" | Out-Null
}

function Run-ServiceTweaks {
	Set-Service -Name "AJRouter" -StartupType "Disabled"
	Set-Service -Name "ALG" -StartupType "Manual"
	Set-Service -Name "AppIDSvc" -StartupType "Manual"
	Set-Service -Name "AppMgmt" -StartupType "Manual"
	Set-Service -Name "AppReadiness" -StartupType "Manual"
	Set-Service -Name "AppVClient" -StartupType "Disabled"
	Set-Service -Name "AppXSvc" -StartupType "Manual"
	Set-Service -Name "Appinfo" -StartupType "Manual"
	Set-Service -Name "AssignedAccessManagerSvc" -StartupType "Disabled"
	Set-Service -Name "AudioEndpointBuilder" -StartupType "Automatic"
	Set-Service -Name "AudioSrv" -StartupType "Automatic"
	Set-Service -Name "AxInstSV" -StartupType "Manual"
	Set-Service -Name "BDESVC" -StartupType "Manual"
	Set-Service -Name "BFE" -StartupType "Automatic"
	Set-Service -Name "BITS" -StartupType "AutomaticDelayedStart"
	Set-Service -Name "BTAGService" -StartupType "Manual"
	Set-Service -Name "BcastDVRUserService_dc2a4" -StartupType "Manual"
	Set-Service -Name "BluetoothUserService_dc2a4" -StartupType "Manual"
	Set-Service -Name "BrokerInfrastructure" -StartupType "Automatic"
	Set-Service -Name "Browser" -StartupType "Manual"
	Set-Service -Name "BthAvctpSvc" -StartupType "Automatic"
	Set-Service -Name "BthHFSrv" -StartupType "Automatic"
	Set-Service -Name "CDPSvc" -StartupType "Manual"
	Set-Service -Name "COMSysApp" -StartupType "Manual"
	Set-Service -Name "CaptureService_dc2a4" -StartupType "Manual"
	Set-Service -Name "CertPropSvc" -StartupType "Manual"
	Set-Service -Name "ClipSVC" -StartupType "Manual"
	Set-Service -Name "ConsentUxUserSvc_dc2a4" -StartupType "Manual"
	Set-Service -Name "CoreMessagingRegistrar" -StartupType "Automatic"
	Set-Service -Name "CredentialEnrollmentManagerUserSvc_dc2a4" -StartupType "Manual"
	Set-Service -Name "CryptSvc" -StartupType "Automatic"
	Set-Service -Name "CscService" -StartupType "Manual"
	Set-Service -Name "DPS" -StartupType "Automatic"
	Set-Service -Name "DcomLaunch" -StartupType "Automatic"
	Set-Service -Name "CscService" -StartupType "Manual"
	Set-Service -Name "DcpSvc" -StartupType "Manual"
	Set-Service -Name "DevQueryBroker" -StartupType "Manual"
	Set-Service -Name "DeviceAssociationBrokerSvc_dc2a4" -StartupType "Manual"
	Set-Service -Name "DeviceAssociationService" -StartupType "Manual"
	Set-Service -Name "DeviceInstall" -StartupType "Manual"
	Set-Service -Name "DevicePickerUserSvc_dc2a4" -StartupType "Manual"
	Set-Service -Name "DevicesFlowUserSvc_dc2a4" -StartupType "Manual"
	Set-Service -Name "Dhcp" -StartupType "Automatic"
	Set-Service -Name "DiagTrack" -StartupType "Disabled"
	Set-Service -Name "DialogBlockingService" -StartupType "Disabled"
	Set-Service -Name "DispBrokerDesktopSvc" -StartupType "Automatic"
	Set-Service -Name "DisplayEnhancementService" -StartupType "Manual"
	Set-Service -Name "DmEnrollmentSvc" -StartupType "Manual"
	Set-Service -Name "Dnscache" -StartupType "Automatic"
	Set-Service -Name "DoSvc" -StartupType "AutomaticDelayedStart"
	Set-Service -Name "DsSvc" -StartupType "Manual"
	Set-Service -Name "DsmSvc" -StartupType "Manual"
	Set-Service -Name "DusmSvc" -StartupType "Automatic"
	Set-Service -Name "EFS" -StartupType "Manual"
	Set-Service -Name "EapHost" -StartupType "Manual"
	Set-Service -Name "EntAppSvc" -StartupType "Manual"
	Set-Service -Name "EventLog" -StartupType "Automatic"
	Set-Service -Name "EventSystem" -StartupType "Automatic"
	Set-Service -Name "FDResPub" -StartupType "Manual"
	Set-Service -Name "Fax" -StartupType "Manual"
	Set-Service -Name "FontCache" -StartupType "Automatic"
	Set-Service -Name "FrameServer" -StartupType "Manual"
	Set-Service -Name "FrameServerMonitor" -StartupType "Manual"
	Set-Service -Name "GraphicsPerfSvc" -StartupType "Manual"
	Set-Service -Name "HomeGroupListener" -StartupType "Manual"
	Set-Service -Name "HomeGroupProvider" -StartupType "Manual"
	Set-Service -Name "HvHost" -StartupType "Manual"
	Set-Service -Name "IEEtwCollectorService" -StartupType "Manual"
	Set-Service -Name "IKEEXT" -StartupType "Manual"
	Set-Service -Name "InstallService" -StartupType "Manual"
	Set-Service -Name "InventorySvc" -StartupType "Manual"
	Set-Service -Name "IpxlatCfgSvc" -StartupType "Manual"
	Set-Service -Name "FontCache" -StartupType "Automatic"
	Set-Service -Name "KeyIso" -StartupType "Automatic"
	Set-Service -Name "KtmRm" -StartupType "Manual"
	Set-Service -Name "LSM" -StartupType "Automatic"
	Set-Service -Name "LanmanServer" -StartupType "Automatic"
	Set-Service -Name "LanmanWorkstation" -StartupType "Automatic"
	Set-Service -Name "LicenseManager" -StartupType "Manual"
	Set-Service -Name "LxpSvc" -StartupType "Manual"
	Set-Service -Name "MSDTC" -StartupType "Manual"
	Set-Service -Name "MSiSCSI" -StartupType "Manual"
	Set-Service -Name "MapsBroker" -StartupType "AutomaticDelayedStart"
	Set-Service -Name "McpManagementService" -StartupType "Manual"
	Set-Service -Name "MessagingService_dc2a4" -StartupType "Manual"
	Set-Service -Name "MicrosoftEdgeElevationService" -StartupType "Manual"
	Set-Service -Name "MixedRealityOpenXRSvc" -StartupType "Manual"
	Set-Service -Name "MpsSvc" -StartupType "Automatic"
	Set-Service -Name "MsKeyboardFilter" -StartupType "Manual"
	Set-Service -Name "NPSMSvc_dc2a4" -StartupType "Manual"
	Set-Service -Name "NaturalAuthentication" -StartupType "Manual"
	Set-Service -Name "NcaSvc" -StartupType "Manual"
	Set-Service -Name "NcbService" -StartupType "Manual"
	Set-Service -Name "NcdAutoSetup" -StartupType "Manual"
	Set-Service -Name "NetTcpPortSharing" -StartupType "Disabled"
	Set-Service -Name "Netlogon" -StartupType "Manual"
	Set-Service -Name "Netman" -StartupType "Manual"
	Set-Service -Name "NgcCtnrSvc" -StartupType "Manual"
	Set-Service -Name "NgcSvc" -StartupType "Manual"
	Set-Service -Name "NlaSvc" -StartupType "Manual"
	Set-Service -Name "OneSyncSvc_dc2a4" -StartupType "Automatic"
	Set-Service -Name "P9RdrService_dc2a4" -StartupType "Manual"
	Set-Service -Name "PNRPAutoReg" -StartupType "Manual"
	Set-Service -Name "PNRPsvc" -StartupType "Manual"
	Set-Service -Name "PcaSvc" -StartupType "Manual"
	Set-Service -Name "PeerDistSvc" -StartupType "Manual"
	Set-Service -Name "PenService_dc2a4" -StartupType "Manual"
	Set-Service -Name "PerfHost" -StartupType "Manual"
	Set-Service -Name "PhoneSvc" -StartupType "Manual"
	Set-Service -Name "PimIndexMaintenanceSvc_dc2a4" -StartupType "Manual"
	Set-Service -Name "PlugPlay" -StartupType "Manual"
	Set-Service -Name "PolicyAgent" -StartupType "Manual"
	Set-Service -Name "Power" -StartupType "Automatic"
	Set-Service -Name "PrintNotify" -StartupType "Manual"
	Set-Service -Name "PrintWorkflowUserSvc_dc2a4" -StartupType "Manual"
	Set-Service -Name "ProfSvc" -StartupType "Automatic"
	Set-Service -Name "PushToInstall" -StartupType "Manual"
	Set-Service -Name "QWAVE" -StartupType "Manual"
	Set-Service -Name "RasAuto" -StartupType "Manual"
	Set-Service -Name "RasMan" -StartupType "Manual"
	Set-Service -Name "RemoteAccess" -StartupType "Disabled"
	Set-Service -Name "RemoteRegistry" -StartupType "Disabled"
	Set-Service -Name "RetailDemo" -StartupType "Manual"
	Set-Service -Name "RmSvc" -StartupType "Manual"
	Set-Service -Name "RpcEptMapper" -StartupType "Automatic"
	Set-Service -Name "RpcLocator" -StartupType "Manual"
	Set-Service -Name "RpcSs" -StartupType "Automatic"
	Set-Service -Name "SCPolicySvc" -StartupType "Manual"
	Set-Service -Name "SCardSvr" -StartupType "Manual"
	Set-Service -Name "SDRSVC" -StartupType "Manual"
	Set-Service -Name "SEMgrSvc" -StartupType "Manual"
	Set-Service -Name "SENS" -StartupType "Automatic"
	Set-Service -Name "SNMPTRAP" -StartupType "Manual"
	Set-Service -Name "SNMPTrap" -StartupType "Manual"
	Set-Service -Name "SSDPSRV" -StartupType "Manual"
	Set-Service -Name "SENS" -StartupType "Automatic"
	Set-Service -Name "SamSs" -StartupType "Automatic"
	Set-Service -Name "ScDeviceEnum" -StartupType "Manual"
	Set-Service -Name "Schedule" -StartupType "Automatic"
	Set-Service -Name "SecurityHealthService" -StartupType "Manual"
	Set-Service -Name "Sense" -StartupType "Manual"
	Set-Service -Name "SensorDataService" -StartupType "Manual"
	Set-Service -Name "SensorService" -StartupType "Manual"
	Set-Service -Name "SensrSvc" -StartupType "Manual"
	Set-Service -Name "SessionEnv" -StartupType "Manual"
	Set-Service -Name "SgrmBroker" -StartupType "Automatic"
	Set-Service -Name "SharedAccess" -StartupType "Manual"
	Set-Service -Name "SharedRealitySvc" -StartupType "Manual"
	Set-Service -Name "ShellHWDetection" -StartupType "Automatic"
	Set-Service -Name "SmsRouter" -StartupType "Manual"
	Set-Service -Name "Spooler" -StartupType "Automatic"
	Set-Service -Name "SstpSvc" -StartupType "Manual"
	Set-Service -Name "StateRepository" -StartupType "Manual"
	Set-Service -Name "StorSvc" -StartupType "Manual"
	Set-Service -Name "SysMain" -StartupType "Automatic"
	Set-Service -Name "SystemEventsBroker" -StartupType "Automatic"
	Set-Service -Name "TabletInputService" -StartupType "Manual"
	Set-Service -Name "TapiSrv" -StartupType "Manual"
	Set-Service -Name "TermService" -StartupType "Automatic"
	Set-Service -Name "TextInputManagementService" -StartupType "Manual"
	Set-Service -Name "Themes" -StartupType "Automatic"
	Set-Service -Name "TieringEngineService" -StartupType "Manual"
	Set-Service -Name "TimeBroker" -StartupType "Manual"
	Set-Service -Name "TimeBrokerSvc" -StartupType "Manual"
	Set-Service -Name "TokenBroker" -StartupType "Manual"
	Set-Service -Name "TrkWks" -StartupType "Automatic"
	Set-Service -Name "TroubleshootingSvc" -StartupType "Manual"
	Set-Service -Name "TrustedInstaller" -StartupType "Manual"
	Set-Service -Name "UI0Detect" -StartupType "Manual"
	Set-Service -Name "UdkUserSvc_dc2a4" -StartupType "Manual"
	Set-Service -Name "UevAgentService" -StartupType "Disabled"
	Set-Service -Name "UmRdpService" -StartupType "Manual"
	Set-Service -Name "UnistoreSvc_dc2a4" -StartupType "Manual"
	Set-Service -Name "UserDataSvc_dc2a4" -StartupType "Manual"
	Set-Service -Name "UserManager" -StartupType "Automatic"
	Set-Service -Name "UsoSvc" -StartupType "Manual"
	Set-Service -Name "VGAuthService" -StartupType "Automatic"
	Set-Service -Name "VMTools" -StartupType "Automatic"
	Set-Service -Name "VSS" -StartupType "Automatic"
	Set-Service -Name "VacSvc" -StartupType "Manual"
	Set-Service -Name "VaultSvc" -StartupType "Automatic"
	Set-Service -Name "VacSvc" -StartupType "Manual"
	Set-Service -Name "W32Time" -StartupType "Manual"
	Set-Service -Name "WEPHOSTSVC" -StartupType "Manual"
	Set-Service -Name "WFDSConMgrSvc" -StartupType "Manual"
	Set-Service -Name "WMPNetworkSvc" -StartupType "Manual"
	Set-Service -Name "WManSvcWManSvc" -StartupType "Manual"
	Set-Service -Name "WManSvc" -StartupType "Manual"
	Set-Service -Name "WPDBusEnum" -StartupType "Manual"
	Set-Service -Name "WSService" -StartupType "Manual"
	Set-Service -Name "WSearch" -StartupType "AutomaticDelayedStart"
	Set-Service -Name "WaaSMedicSvc" -StartupType "Manual"
	Set-Service -Name "WalletService" -StartupType "Manual"
	Set-Service -Name "WarpJITSvc" -StartupType "Manual"
	Set-Service -Name "WbioSrvc" -StartupType "Manual"
	Set-Service -Name "Wcmsvc" -StartupType "Automatic"
	Set-Service -Name "WdNisSvc" -StartupType "Manual"
	Set-Service -Name "WdiServiceHost" -StartupType "Manual"
	Set-Service -Name "WdiSystemHost" -StartupType "Manual"
	Set-Service -Name "WebClient" -StartupType "Manual"
	Set-Service -Name "Wecsvc" -StartupType "Manual"
	Set-Service -Name "WerSvc" -StartupType "Manual"
	Set-Service -Name "WiaRpc" -StartupType "Manual"
	Set-Service -Name "WinDefend" -StartupType "Automatic"
	Set-Service -Name "WcsPlugInService" -StartupType "Manual"
	Set-Service -Name "WinHttpAutoProxySvc" -StartupType "Manual"
	Set-Service -Name "WinRM" -StartupType "Manual"
	Set-Service -Name "Winmgmt" -StartupType "Automatic"
	Set-Service -Name "WlanSvc" -StartupType "Automatic"
	Set-Service -Name "WpcMonSvc" -StartupType "Manual"
	Set-Service -Name "WpnService" -StartupType "Manual"
	Set-Service -Name "WpnUserService_dc2a4" -StartupType "Automatic"
	Set-Service -Name "WwanSvc" -StartupType "Manual"
	Set-Service -Name "XblAuthManager" -StartupType "Manual"
	Set-Service -Name "XblGameSave" -StartupType "Manual"
	Set-Service -Name "XboxGipSvc" -StartupType "Manual"
	Set-Service -Name "XboxNetApiSvc" -StartupType "Manual"
	Set-Service -Name "autotimesvc" -StartupType "Manual"
	Set-Service -Name "bthserv" -StartupType "Manual"
	Set-Service -Name "camsvc" -StartupType "Manual"
	Set-Service -Name "cbdhsvc_dc2a4" -StartupType "Manual"
	Set-Service -Name "cloudidsvc" -StartupType "Manual"
	Set-Service -Name "dcsvc" -StartupType "Manual"
	Set-Service -Name "defragsvc" -StartupType "Manual"
	Set-Service -Name "diagnosticshub.standardcollector.service" -StartupType "Manual"
	Set-Service -Name "diagsvc" -StartupType "Manual"
	Set-Service -Name "dmwappushservice" -StartupType "Manual"
	Set-Service -Name "dot3svc" -StartupType "Manual"
	Set-Service -Name "edgeupdate" -StartupType "Manual"
	Set-Service -Name "edgeupdatem" -StartupType "Manual"
	Set-Service -Name "embeddedmode" -StartupType "Manual"
	Set-Service -Name "fdPHost" -StartupType "Manual"
	Set-Service -Name "fhsvc" -StartupType "Manual"
	Set-Service -Name "gpsvc" -StartupType "Automatic"
	Set-Service -Name "hidserv" -StartupType "Manual"
	Set-Service -Name "icssvc" -StartupType "Manual"
	Set-Service -Name "iphlpsvc" -StartupType "Automatic"
	Set-Service -Name "lfsvc" -StartupType "Manual"
	Set-Service -Name "lltdsvc" -StartupType "Manual"
	Set-Service -Name "lmhosts" -StartupType "Manual"
	Set-Service -Name "iphlpsvc" -StartupType "Automatic"
	Set-Service -Name "mpssvc" -StartupType "Automatic"
	Set-Service -Name "msiserver" -StartupType "Manual"
	Set-Service -Name "netprofm" -StartupType "Manual"
	Set-Service -Name "nsi" -StartupType "Automatic"
	Set-Service -Name "p2pimsvc" -StartupType "Manual"
	Set-Service -Name "p2psvc" -StartupType "Manual"
	Set-Service -Name "perceptionsimulation" -StartupType "Manual"
	Set-Service -Name "pla" -StartupType "Manual"
	Set-Service -Name "seclogon" -StartupType "Manual"
	Set-Service -Name "shpamsvc" -StartupType "Disabled"
	Set-Service -Name "smphost" -StartupType "Manual"
	Set-Service -Name "spectrum" -StartupType "Manual"
	Set-Service -Name "sppsvc" -StartupType "AutomaticDelayedStart"
	Set-Service -Name "ssh-agent" -StartupType "Disabled"
	Set-Service -Name "svsvc" -StartupType "Manual"
	Set-Service -Name "swprv" -StartupType "Manual"
	Set-Service -Name "tiledatamodelsvc" -StartupType "Automatic"
	Set-Service -Name "tzautoupdate" -StartupType "Disabled"
	Set-Service -Name "uhssvc" -StartupType "Disabled"
	Set-Service -Name "upnphost" -StartupType "Manual"
	Set-Service -Name "vds" -StartupType "Manual"
	Set-Service -Name "vm3dservice" -StartupType "Manual"
	Set-Service -Name "vmicguestinterface" -StartupType "Manual"
	Set-Service -Name "vmicheartbeat" -StartupType "Manual"
	Set-Service -Name "vmickvpexchange" -StartupType "Manual"
	Set-Service -Name "vmicrdv" -StartupType "Manual"
	Set-Service -Name "vmicshutdown" -StartupType "Manual"
	Set-Service -Name "vmictimesync" -StartupType "Manual"
	Set-Service -Name "vmicvmsession" -StartupType "Manual"
	Set-Service -Name "vmicvss" -StartupType "Manual"
	Set-Service -Name "vmvss" -StartupType "Manual"
	Set-Service -Name "wbengine" -StartupType "Manual"
	Set-Service -Name "wcncsvc" -StartupType "Manual"
	Set-Service -Name "webthreatdefsvc" -StartupType "Manual"
	Set-Service -Name "webthreatdefusersvc_dc2a4" -StartupType "Automatic"
	Set-Service -Name "wercplsupport" -StartupType "Manual"
	Set-Service -Name "wisvc" -StartupType "Manual"
	Set-Service -Name "wlidsvc" -StartupType "Manual"
	Set-Service -Name "wlpasvc" -StartupType "Manual"
	Set-Service -Name "wmiApSrv" -StartupType "Manual"
	Set-Service -Name "workfolderssvc" -StartupType "Manual"
	Set-Service -Name "wscsvc" -StartupType "AutomaticDelayedStart"
	Set-Service -Name "wuauserv" -StartupType "Manual"
	Set-Service -Name "wudfsvc" -StartupType "Manual"
}
