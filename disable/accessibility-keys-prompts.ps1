Write-Output "Disabling Accessibility Keys Prompts..."
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506" | Out-Null
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "58" | Out-Null
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "122" | Out-Null
Write-Output "Done"
