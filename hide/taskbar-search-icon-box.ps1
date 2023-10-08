Write-Output "Hiding Taskbar Search icon / box..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0 | Out-Null
Write-Output "Done"
