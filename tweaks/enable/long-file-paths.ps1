Write-Output "Enabling NTFS Paths with Length Over 260 Characters..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Type DWord -Value 1 | Out-Null
Write-Output "Done"
