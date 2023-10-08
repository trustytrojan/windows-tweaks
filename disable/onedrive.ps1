Write-Output "Disabling OneDrive..."

Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
Start-Sleep -s 2
$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"

If (!(Test-Path $onedrive)) {
	$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
}

Start-Process $onedrive "/uninstall" -NoNewWindow -Wait | Out-Null
Start-Sleep -s 2
Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
Start-Sleep -s 2

If ((Get-ChildItem -Path "$env:USERPROFILE\OneDrive" -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
	Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
}

Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null

If (!(Test-Path "HKCR:")) {
	New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
}
Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue | Out-Null
Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue | Out-Null

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1 | Out-Null

Write-Output "Done"
