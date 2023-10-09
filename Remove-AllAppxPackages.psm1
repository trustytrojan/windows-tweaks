function Remove-AllAppxPackages {
	param(
 		[Parameter()]
  		[string]$ExceptRegex = ""
	)

	$toRemove = Get-AppxPackage | ?{ $_.Name -notmatch $ExceptRegex }

	Write-Host "Removing the below apps:" -Background Blue
	$toRemove | %{ $_.Name }
	Write-Host "Do you want to proceed? [Y/n]" -NoNewLine -Background Blue
	Write-Host " " -NoNewLine

	if ((Read-Host) -notin "", "Y", "y") {
		exit
	}

	foreach ($package in $toRemove) {
		Write-Host "Removing app: $($package.Name)" -Foreground Blue
		Remove-AppxPackage $package
	}

	Write-Host "Finished removing apps!" -Foreground Green
}
