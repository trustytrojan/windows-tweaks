param(
	[Parameter(Mandatory)]
	[string]$MountedImagePath
)

$keepRegex = "Microsoft\.(DesktopAppInstaller|ScreenSketch|StorePurchaseApp|WindowsStore).+"
$toRemove = Get-ProvisionedAppxPackage -Path $MountedImagePath | ?{ $_.PackageName -notmatch $keepRegex } | %{ $_.PackageName }

Write-Host "Removing the below apps:" -Background Blue
$toRemove
Write-Host "Do you want to proceed? [Y/n]" -NoNewLine -Background Blue
Write-Host " " -NoNewLine

if ((Read-Host) -notin "", "Y", "y") {
	exit
}

foreach ($packageName in $toRemove) {
	Write-Host "`nRemoving $packageName" -Foreground Blue
	Remove-ProvisionedAppxPackage -Path $MountedImagePath -PackageName $packageName
}

Write-Host "Finished removing apps!" -Foreground Green
