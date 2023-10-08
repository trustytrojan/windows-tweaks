# https://github.com/GGamer6458/postsetup
# Network Optimizations (Credit to TCP Optimizer by https://www.speedguide.net/)
Write-Output "Runnning Network Optimizations..."
Set-NetTCPSetting -SettingName internet -AutoTuningLevelLocal disabled | Out-Null
Set-NetTCPSetting -SettingName internet -ScalingHeuristics disabled | Out-Null
netsh int tcp set supplemental internet congestionprovider=ctcp
Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing disabled | Out-Null
Set-NetOffloadGlobalSetting -ReceiveSideScaling disabled | Out-Null
Disable-NetAdapterLso -Name * | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" -Name "explorer.exe" -Type DWord -Value 10 | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" -Name "iexplore.exe" -Type DWord -Value 10 | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" -Name "explorer.exe" -Type DWord -Value 10 | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" -Name "iexplore.exe" -Type DWord -Value 10 | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "LocalPriority" -Type DWord -Value 4 | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "HostsPriority" -Type DWord -Value 5 | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "DnsPriority" -Type DWord -Value 6 | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "NetbtPriority" -Type DWord -Value 7 | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Type DWord -Value 0 | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" -Name "Do Not use NLA" -Type String -Value 1 | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "AlwaysOn" -Type DWord -Value 1 | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xffffffff | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NoLazyMode" -Type DWord -Value 1 | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0 | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "Size" -Type DWord -Value 3 | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Type DWord -Value 1 | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxUserPort" -Type DWord -Value 65534 | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpTimedWaitDelay" -Type DWord -Value 30 | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" -Name "TCPNoDelay" -Type String -Value "" | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Type String -Value "" | Out-Null
Set-NetTCPSetting -SettingName internet -EcnCapability disabled | Out-Null
Set-NetOffloadGlobalSetting -Chimney disabled | Out-Null
Set-NetTCPSetting -SettingName internet -Timestamps disabled | Out-Null
Set-NetTCPSetting -SettingName internet -MaxSynRetransmissions 2 | Out-Null
Set-NetTCPSetting -SettingName internet -NonSackRttResiliency disabled | Out-Null
Set-NetTCPSetting -SettingName internet -InitialRtoMs 2000 | Out-Null
Set-NetTCPSetting -SettingName internet -MinRtoMs 300 | Out-Null
netsh interface ipv4 set subinterface "Ethernet 2" mtu=1492 store=persistent
netsh interface ipv6 set subinterface "Ethernet 2" mtu=1492 store=persistent
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{faf0c941-8197-4a30-b959-e93cf2efaf9c}" -Name "TcpAckFrequency" -Type String -Value "" | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{faf0c941-8197-4a30-b959-e93cf2efaf9c}" -Name "TcpDelAckTicks" -Type String -Value "" | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{faf0c941-8197-4a30-b959-e93cf2efaf9c}" -Name "TCPNoDelay" -Type String -Value "" | Out-Null
netsh interface ipv4 set subinterface "Ethernet" mtu=1492 store=persistent
netsh interface ipv6 set subinterface "Ethernet" mtu=1492 store=persistent
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{eca522f4-2df2-4e86-a441-ebcec874e655}" -Name "TcpAckFrequency" -Type String -Value "" | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{eca522f4-2df2-4e86-a441-ebcec874e655}" -Name "TcpDelAckTicks" -Type String -Value "" | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{eca522f4-2df2-4e86-a441-ebcec874e655}" -Name "TCPNoDelay" -Type String -Value "" | Out-Null
Write-Output "Done"
