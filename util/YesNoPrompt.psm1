function Show-YesNoPrompt {
	param(
		[Parameter(Mandatory=$true)]
		[string]$Question,

		[Parameter(Mandatory=$true)]
		[ValidateSet("Y", "N")]
		[string]$Default,

		[Parameter()]
		[System.ConsoleColor]$ForegroundColor,

		[Parameter()]
		[System.ConsoleColor]$BackgroundColor
	)

	Write-Host "$Question [Y/n]" -NoNewLine
	Write-Host " " -NoNewLine

	return (Read-Host) -in "", "Y", "y"
}