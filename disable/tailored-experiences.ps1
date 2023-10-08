Write-Output "Disabling Tailored Experiences..."

If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent")) {
	New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1 | Out-Null

Write-Output "Done"
