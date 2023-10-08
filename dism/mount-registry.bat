@echo off

if "%1"=="" (
	echo You must provide a path to a Windows installation.
	echo "Usage: %0 <image path>"
	exit
)

echo Mounting Image Registry for Offline Editing
reg load HKLM\TK_COMPONENTS "%1\Windows\System32\config\COMPONENTS" >nul
reg load HKLM\TK_DEFAULT "%1\Windows\System32\config\default" >nul
reg load HKLM\TK_NTUSER "%1\Users\Default\ntuser.dat" >nul
reg load HKLM\TK_SOFTWARE "%1\Windows\System32\config\SOFTWARE" >nul
reg load HKLM\TK_SYSTEM "%1\Windows\System32\config\SYSTEM" >nul
