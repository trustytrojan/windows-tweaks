param(
	[Parameter(Mandatory)]
	[string]$Path
)

$keepRegex = ".*RDC.*"
$toDisable = Get-WindowsOptionalFeature -Path $Path | ?{ ($_.State -eq "Enabled") -and ($_.FeatureName -notmatch $keepRegex) } | %{ $_.FeatureName }

Write-Host "Disabling the below features:" -Background Blue
$toDisable
Write-Host "Do you want to proceed? [Y/n]" -NoNewLine -Background Blue
Write-Host " " -NoNewLine

if ((Read-Host) -notin "", "Y", "y") {
	exit
}

foreach ($featureName in $toDisable) {
	Write-Host "Disabling: $featureName" -Foreground Blue
	Disable-WindowsOptionalFeature -Path $Path -FeatureName $featureName
}

Write-Host "Finished disabling features!" -Foreground Green
