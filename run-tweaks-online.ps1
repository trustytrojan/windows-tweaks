Import-Module .\tweaks.psm1
Import-Module .\Remove-AllAppxPackages.psm1
Import-Module .\dism\Disable-AllWindowsOptionalFeatures.psm1

Remove-AllAppxPackages -ExceptRegex "Microsoft\.(WindowsStore|DesktopAppInstaller|ScreenSketch)"
Disable-AllWindowsOptionalFeatures -ExceptRegex ".*RDC.*"

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
