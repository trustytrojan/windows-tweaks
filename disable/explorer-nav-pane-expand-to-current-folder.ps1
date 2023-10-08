Write-Output "Disabling Navigation Pane Expanding to Current Folder..."
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -ErrorAction SilentlyContinue | Out-Null
Write-Output "Done"
