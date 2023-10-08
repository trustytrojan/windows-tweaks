Write-Output "Hiding All Icons from Desktop..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 1 | Out-Null
Write-Output "Done"
