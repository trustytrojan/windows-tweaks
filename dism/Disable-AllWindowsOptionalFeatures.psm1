function Disable-AllWindowsOptionalFeatures {
	param(
		[Parameter()]
		[string]$ExceptRegex,

		[Parameter()]
		[string]$Path
	)

	try {
		if ($Path) {
			Write-Debug "Using Path"
			$optionalFeatures = Get-WindowsOptionalFeature -Path $Path
		} else {
			Write-Debug "Using Online"
			$optionalFeatures = Get-WindowsOptionalFeature -Online
		}
	} catch {
		Write-Host $_ -ForegroundColor Red
		return
	}

	if ($ExceptRegex) {
		$filter = { ($_.State -eq "Enabled") -and ($_.FeatureName -notmatch $ExceptRegex) }
	} else {
		$filter = { $_.State -eq "Enabled" }
	}

	$toDisable = $optionalFeatures | Where-Object $filter | ForEach-Object { $_.FeatureName }

	if ($toDisable.Length -eq 0) {
		Write-Host "There are no features to disable." -ForegroundColor Green
	}

	Write-Host "Disabling the below features:" -ForegroundColor Blue
	$toDisable
	Write-Host "Do you want to proceed? [Y/n]" -NoNewLine -ForegroundColor Blue
	Write-Host " " -NoNewLine

	if ((Read-Host) -notin "", "Y", "y") {
		return
	}

	try {
		if ($Path) {
			Disable-WindowsOptionalFeature -Path $Path -FeatureName $toDisable
		} else {
			Disable-WindowsOptionalFeature -Online -FeatureName $toDisable
		}
	} catch {
		Write-Host $_ -ForegroundColor Red
		return
	}

	Write-Host "Finished disabling features!" -ForegroundColor Green
}
