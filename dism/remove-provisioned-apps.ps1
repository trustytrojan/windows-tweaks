param(
	[Parameter(Mandatory)]
	[string]$Path
)

$keepRegex = "Microsoft\.(DesktopAppInstaller|ScreenSketch|StorePurchaseApp|WindowsStore).+"
$toRemove = Get-AppxProvisionedPackage -Path $Path | ?{ $_.PackageName -notmatch $keepRegex } | %{ $_.PackageName }

Write-Host "Removing the below apps:" -Background Blue
$toRemove
Write-Host "Do you want to proceed? [Y/n]" -NoNewLine -Background Blue
Write-Host " " -NoNewLine

if ((Read-Host) -notin "", "Y", "y") {
	exit
}

foreach ($packageName in $toRemove) {
	Write-Host "`nRemoving $packageName" -Foreground Blue
	Remove-AppxProvisionedPackage -Path $Path -PackageName $packageName
}

Write-Host "Finished removing apps!" -Foreground Green

function Remove-AllProvisionedAppxPackages {
	param(
		[Parameter()]
		[string]$ExceptRegex,

		[Parameter()]
		[string]$Path
	)


}
