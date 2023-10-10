function Remove-AllAppxProvisionedPackages {
	param (
		[Parameter()]
		[string]$ExceptRegex,

		[Parameter()]
		[string]$Path
	)

	try {
		if ($Path) {
			$appxPackages = Get-AppxProvisionedPackage -Path $Path
		} else {
			$appxPackages = Get-AppxProvisionedPackage -Online
		}
	} catch {
		Write-Host $_ -ForegroundColor Red
		return
	}

	if ($ExceptRegex) {
		$toRemove = $appxPackages | Where-Object { $_.DisplayName -notmatch $ExceptRegex }
	} else {
		$toRemove = $appxPackages
	}

	if ($toRemove.Count -eq 0) {
		Write-Host "There are no provisioned AppX packages to remove." -ForegroundColor Green
		return
	}

	Write-Host "The below provisioned AppX packages will be removed:" -ForegroundColor Blue
	$toRemove | ForEach-Object { $_.DisplayName }
	Write-Host "Do you want to proceed? [Y/n]" -NoNewLine -ForegroundColor Blue
	Write-Host " " -NoNewLine

	if ((Read-Host) -notin "", "Y", "YES", "y", "yes") {
		return
	}

	if ($Path) {
		$removeCall = { Remove-AppxProvisionedPackage $appxPackage -Path $Path }
	} else {
		$removeCall = { Remove-AppxProvisionedPackage $appxPackage -Online }
	}

	foreach ($appxPackage in $toRemove) {
		Write-Host "Removing $($appxPackage.DisplayName)..." -ForegroundColor Blue
		$removeCall.Invoke()
	}

	Write-Host "Finished removing apps!" -ForegroundColor Green
}
