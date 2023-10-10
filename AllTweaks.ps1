Import-Module ".\modules\RegistryTweaks.psm1"
Import-Module ".\modules\Remove-AllAppxPackages.psm1"
Import-Module ".\modules\Disable-AllWindowsOptionalFeatures.psm1"
Import-Module ".\modules\Remove-AllWindowsCapabilities.psm1"

Remove-AllAppxPackages -ExceptRegex "Microsoft\.(WindowsStore|DesktopAppInstaller|ScreenSketch)"
Disable-AllWindowsOptionalFeatures -ExceptRegex ".*RDC.*"
Remove-AllWindowsCapabilities -ExceptRegex "(Microsoft\.(Wallpaper|Windows\.(Wifi|Ethernet))|Windows\.Kernel.*|OpenSSH.+|Hello\.Face.+)"

Disable-AccessibilityKeyPrompts
Disable-ActivityHistory
Disable-AdvertisingID
Disable-ApplicationSuggestionsAndAutomaticInstallation
Disable-AutomaticMapsUpdates
Disable-ErrorReporting
Disable-NavPaneExpandToCurrentFolder
Disable-ExplorerRecentFilesList
Disable-Feedback
Disable-GameDVR
Disable-LocationTracking
Disable-NewContextMenu
Disable-OneDrive
Disable-SearchBloat
Disable-StorageSense
Disable-TailoredExperiences
Disable-Telemetry
Disable-UnknownExtensionAppSuggestion
Disable-WifiSense

Enable-LongFilePaths
Enable-ExplorerFileExtensions

Hide-DesktopIcons
Hide-ExplorerRecentFiles
Hide-StartMenuRecentlyAdded
Hide-TaskbarTaskView
Hide-TaskbarPeople
Hide-TaskbarSearch

Uninstall-Teams

Show-AllTrayIcons

Optimize-Network
Optimize-Services
