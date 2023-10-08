Write-Output "Disabling Automatic Maps Updates..."
Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0 | Out-Null
Write-Output "Done"
