Write-Output "Removing Teams..."

$TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams')
$TeamsUpdateExePath = [System.IO.Path]::Combine($TeamsPath, 'Update.exe')
Stop-Process -Name "*teams*" -Force -ErrorAction SilentlyContinue

if ([System.IO.File]::Exists($TeamsUpdateExePath)) {
	# Uninstall app
	$proc = Start-Process $TeamsUpdateExePath -uninstall -s -PassThru | Out-Null
	$proc.WaitForExit()
}

Get-AppxPackage "*Teams*" | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage "*Teams*" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

if ([System.IO.Directory]::Exists($TeamsPath)) {
	Remove-Item $TeamsPath -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
}

# Uninstall from Uninstall registry key UninstallString
$us = (Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | Get-ItemProperty | Where-Object { $_.DisplayName -like '*Teams*'}).UninstallString
if ($us.Length -gt 0) {
	$us = ($us.Replace('I', 'uninstall') + 'quiet').Replace('', '')
	$FilePath = ($us.Substring(0, $us.IndexOf('.exe') + 4).Trim())
	$ProcessArgs = ($us.Substring($us.IndexOf('.exe') + 5).Trim().replace('', ''))
	$proc = Start-Process -FilePath $FilePath -Args $ProcessArgs -PassThru | Out-Null
	$proc.WaitForExit()
}

Write-Output "Done"
