Write-Output "Disabling Storage Sense..."
Remove-Item -Path \"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy\" -Recurse -ErrorAction SilentlyContinue | Out-Null
Write-Output "Done"
