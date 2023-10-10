function Remove-AllWindowsCapabilities {
	param (
		[Parameter()]
		[string]$ExceptRegex,

		[Parameter()]
		[string]$Path
	)

	if ($ExceptRegex) {
		$filter = { ($_.State -eq "Installed") -and ($_.Name -notmatch $ExceptRegex) }
	} else {
		$filter = { $_.State -eq "Installed" }
	}

	try {
		if ($Path) {
			$toRemove = Get-WindowsCapability -Path $Path | Where-Object $filter
			$removeCall = { Remove-WindowsCapability $capability -Path $Path }
		} else {
			$toRemove = Get-WindowsCapability -Online | Where-Object $filter
			$removeCall = { Remove-WindowsCapability $capability -Online }
		}
	} catch {
		Write-Host $_ -ForegroundColor Red
		return
	}

	Write-Host "The below capabilities will be removed:" -ForegroundColor Blue
	$toRemove | ForEach-Object { $_.Name }
	Write-Host "Do you want to proceed? [Y/n]" -NoNewLine -ForegroundColor Blue
	Write-Host " " -NoNewLine

	foreach ($capability in $toRemove) {
		Write-Host "Removing capability: $capabilityName" -Foreground Blue
		$removeCall.Invoke()
	}

	Write-Host "Finished removing capabilities!" -ForegroundColor Green
}
