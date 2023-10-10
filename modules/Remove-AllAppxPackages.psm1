function Remove-AllAppxPackages {
	param (
		[Parameter()]
		[string]$ExceptRegex
	)

	if ($ExceptRegex) {
		$toRemove = Get-AppxPackage | Where-Object { $_.Name -notmatch $ExceptRegex }
	} else {
		$toRemove = Get-AppxPackage
	}

	Write-Host "AppX packages to remove:" -ForegroundColor Blue
	$toRemove | ForEach-Object { $_.Name }
	Write-Host "Do you want to proceed? [Y/n]" -NoNewLine -BackgroundColor Blue
	Write-Host " " -NoNewLine

	if ((Read-Host) -notin "", "Y", "YES", "y", "yes") {
		return
	}

	foreach ($package in $toRemove) {
		Write-Host "Removing app: $($package.Name)" -ForegroundColor Blue
		Remove-AppxPackage $package
	}

	Write-Host "Finished removing apps!" -ForegroundColor Green
}
