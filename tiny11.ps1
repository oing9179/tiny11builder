# Tiny11 Image Builder Script

param(
	[Parameter(HelpMessage='Enable non-interactive mode for automated script execution.')]
	[switch]$NonInteractive = $False,
	[Parameter(HelpMessage='Where to keep temporary data.')]
	[string]$ScratchDir = $Env:TEMP,
	[string]$DriveLetter,
	[Parameter(HelpMessage='Ordinal of the input WIM/ESD image, value starts from 1.')]
	[int]$ImageOrdinal = 0,
	[switch]$RemoveEdgeWebBrowser = $False,
	[Parameter(HelpMessage='Disable Windows Defender.')]
	[switch]$DisableWinDef = $False,
	[Parameter(HelpMessage='Skip cleanning up working directory.')]
	[switch]$SkipCleanUp = $False,
	[Parameter(HelpMessage='Perform clean up then exit.')]
	[switch]$PerformCleanUp = $False
)

$theAdminGroup = $Null
$workingDir = "$ScratchDir\tiny11"
$wimMountPoint = "$ScratchDir\tiny11_wim_mount_point"

function Tiny11-Main {
	$result = $False
	Tiny11-RunSelfAsAdminIfRequired -Returns ([ref]$result)
	if ($result) {
		exit
	}

	if ($PerformCleanUp) {
		Tiny11-ScratchDirCleanUp
		exit
	}

	Start-Transcript -Path "$PSScriptRoot\tiny11.log"

	try {
		Tiny11-SetupConsole

		$result = $False
		Tiny11-DownloadOscdimgExecutable -Returns ([ref]$result)
		if (!$result) {
			throw "Failed to download 'oscdimg.exe'."
		}

		Tiny11-CopyWindowsInstallationFiles -Returns ([ref]$result)
		if (!$result) {
			throw 'Failed to copy Windows installation files.'
		}
		Tiny11-MountImageToWorkOnIt -Returns ([ref]$result)
		if (!$result) {
			throw 'Failed to mount Windows installation image.'
		}

		Tiny11-RemoveProvisionedAppxPackages
		Tiny11-RemoveEdgeWebBrowser
		Tiny11-RemoveOneDrive
		Tiny11-ApplyRegistryOptimizations
		Tiny11-ImageCleanUpAndUnmountAndExport

		Tiny11-BypassingSystemRequirementsOnSetupImage

		Tiny11-CreateBootableISO
	} finally {
		Stop-Transcript
	}

	if(!$SkipCleanUp) {
		Tiny11-ScratchDirCleanUp
	}
}

# Check and run the script as admin if required
function Tiny11-RunSelfAsAdminIfRequired {
	param([Parameter()][ref]$Returns)
	$Returns.Value = $False

	$adminSID = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
	$script:theAdminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])
	$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	$myWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($myWindowsID)
	$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
	if (!$myWindowsPrincipal.IsInRole($adminRole))
	{
		Tiny11-TtyPrint 'Restarting Tiny11 Image Creator as admin..'
		$newProcess = New-Object System.Diagnostics.ProcessStartInfo 'PowerShell';
		$newProcess.Arguments = $script:MyInvocation.MyCommand.Definition;
		$newProcess.Verb = 'runas';
		[System.Diagnostics.Process]::Start($newProcess);

		$Returns.Value = $True
		return
	}
	return
}

function Tiny11-SetupConsole {
	if (!$NonInteractive) {
		Clear-Host
		$Host.UI.RawUI.WindowTitle = 'Tiny11 Image Creator'
	}
	Tiny11-TtyPrint 'Welcome to the Tiny11 Image Creator! Release: 4abfcdca'
}

function Tiny11-DownloadOscdimgExecutable {
	param([Parameter()][ref]$Returns)
	$Returns.Value = $False

	$oscdimgExeFile = "$PSScriptRoot\oscdimg.exe"
	if (Test-Path -Path $oscdimgExeFile) {
		$Returns.Value = $True
		return
	}

	$url = 'https://msdl.microsoft.com/download/symbols/oscdimg.exe/3D44737265000/oscdimg.exe'
	Tiny11-TtyPrint 'Downloading oscdimg.exe...'
	Invoke-WebRequest -Uri $url -OutFile "$oscdimgExeFile"
	if (-not (Test-Path $oscdimgExeFile)) {
		Tiny11-TtyPrint "Failed to download 'oscdimg.exe', you may have to download it your self and place under path '$oscdimgExeFile'."
		Tiny11-TtyPrint "Download URL for 'oscdimg.exe': $url"
		return
	}

	$Returns.Value = $True
}

function Tiny11-CopyWindowsInstallationFiles {
	param([Parameter()][ref]$Returns)
	$Returns.Value = $False

	$hostArchitecture = $Env:PROCESSOR_ARCHITECTURE
	New-Item -ItemType Directory -Force -Path "$workingDir\sources" 2>&1 | Out-Null

	$letter = $DriveLetter
	if (!$NonInteractive) {
		Tiny11-TtyPrint -NoNewLine 'Enter the drive letter of the mounted Windows 11 ISO: '
		$letter = Read-Host
	}
	$matcher = $letter | Select-String "^([a-zA-z]{1}):?$"
	if ($matcher.matches.Count -eq 0 -or $matcher.matches.groups.Count -lt 1) {
		Tiny11-TtyPrint "Invalid drive letter: $letter"
		return
	}
	$DriveLetter = "$($matcher.matches.groups[1]):"

	if (Test-Path "$DriveLetter\sources\install.esd") {
		Tiny11-TtyPrint 'Found install.esd.'

		$ordinal = $ImageOrdinal
		if (!$NonInteractive) {
			& dism /English /Get-WimInfo /WimFile:"$DriveLetter\sources\install.esd"
			Tiny11-TtyPrint -NoNewLine "Enter the index of the image: "
			$ordinal = Read-Host
		}
		try {
			[int]$ordinal | Out-Null
		} catch {
			Tiny11-TtyPrint "Error: '$ordinal' isn't a number."
			return
		}

		Tiny11-TtyPrint 'Converting install.esd to install.wim...'
		& dism /Export-Image /SourceImageFile:"$DriveLetter\sources\install.esd" /SourceIndex:$ordinal /DestinationImageFile:"$workingDir\sources\install.wim" /Compress:fast /CheckIntegrity
		if ($LastExitCode -ne 0) {
			return
		}
	} elseif (Test-Path "$DriveLetter\sources\install.wim") {
		# Do nothing.
	} else {
		Tiny11-TtyPrint "Can't find Windows installation files on drive $DriveLetter."
		return
	}

	Tiny11-TtyPrint 'Copying Windows installation files...'
	Copy-Item -Path "$DriveLetter\*" -Destination "$workingDir" -Recurse -Force 2>&1 | Out-Null

	Set-ItemProperty -Path "$workingDir\sources\install.esd" -Name IsReadOnly -Value $False 2>&1 | Out-Null
	Remove-Item "$workingDir\sources\install.esd" 2>&1 | Out-Null

	$Returns.Value = $True
}

function Tiny11-MountImageToWorkOnIt {
	param([Parameter()][ref]$Returns)
	$Returns.Value = $False

	$wimFilePath = "$workingDir\sources\install.wim"
	$output = & dism /English /Get-WimInfo /WimFile:$wimFilePath
	$matcher = $output | Select-String "^Index : (\d+)$"
	if ($matcher.matches.Count -eq 1) {
		$ImageOrdinal = 1
	}
	if ($ImageOrdinal -ne 1 -and !$NonInteractive) {
		Write-Output $output
		Tiny11-TtyPrint -NoNewLine 'Enter the image index: '
		$ordinal = Read-Host
		try {
			$ImageOrdinal = [int]$ordinal
		} catch {
			Tiny11-TtyPrint "Error: '$ordinal' isn't a number."
			return
		}
	}

	Tiny11-TtyPrint 'Mounting image...'
	& takeown /f $wimFilePath | Out-Null
	& icacls $wimFilePath /grant "$($theAdminGroup.Value):(F)" | Out-Null
	Set-ItemProperty -Path $wimFilePath -Name IsReadOnly -Value $False | Out-Null
	New-Item -ItemType Directory -Force -Path "$wimMountPoint" | Out-Null
	& dism /English /Get-WimInfo /WimFile:"$wimFilePath" /Index:$ImageOrdinal
	& dism /English /Mount-Image /ImageFile:"$wimFilePath" /Index:$ImageOrdinal /MountDir:"$wimMountPoint"
	$Returns.Value = $True
}

function Tiny11-RemoveProvisionedAppxPackages {
	Tiny11-TtyPrint 'Removing Appx packages...'

	$packagePrefixes = @(
		### Common Apps / Client editions all
		# 'Microsoft.WindowsStore',
		# 'Microsoft.StorePurchaseApp',
		# 'Microsoft.SecHealthUI',
		# 'Microsoft.DesktopAppInstaller',
		# 'Microsoft.Windows.Photos',
		# 'Microsoft.WindowsCamera',
		# 'Microsoft.WindowsNotepad',
		# 'Microsoft.Paint',
		# 'Microsoft.WindowsTerminal',
		'MicrosoftWindows.Client.WebExperience',
		# 'Microsoft.WindowsAlarms',
		# 'Microsoft.WindowsCalculator',
		'Microsoft.WindowsMaps',
		'Microsoft.MicrosoftStickyNotes',
		# 'Microsoft.ScreenSketch',
		'microsoft.windowscommunicationsapps',
		'Microsoft.People',
		'Microsoft.BingNews',
		'Microsoft.BingWeather',
		'Microsoft.MicrosoftSolitaireCollection',
		'Microsoft.MicrosoftOfficeHub',
		'Microsoft.WindowsFeedbackHub',
		'Microsoft.GetHelp',
		'Microsoft.Getstarted',
		'Microsoft.Todos',
		'Microsoft.XboxSpeechToTextOverlay',
		'Microsoft.XboxGameOverlay',
		# 'Microsoft.XboxIdentityProvider',
		'Microsoft.PowerAutomateDesktop',
		'Microsoft.549981C3F5F10',
		'MicrosoftCorporationII.QuickAssist',
		'MicrosoftCorporationII.MicrosoftFamily',
		'Microsoft.OutlookForWindows',
		'MicrosoftTeams',
		'Microsoft.Windows.DevHome',
		'Microsoft.BingSearch',
		'Microsoft.ApplicationCompatibilityEnhancements',
		'MicrosoftWindows.CrossDevice',
		'MSTeams',

		### Media Apps / Client non-N editions
		'Microsoft.ZuneMusic',
		'Microsoft.ZuneVideo',
		'Microsoft.YourPhone',
		'Microsoft.WindowsSoundRecorder',
		'Microsoft.GamingApp',
		'Microsoft.XboxGamingOverlay',
		'Microsoft.Xbox.TCUI',
		'Clipchamp.Clipchamp',

		### Media Codecs / Client non-N editions, Team edition
		# 'Microsoft.WebMediaExtensions',
		# 'Microsoft.RawImageExtension',
		# 'Microsoft.HEIFImageExtension',
		# 'Microsoft.HEVCVideoExtension',
		# 'Microsoft.VP9VideoExtensions',
		# 'Microsoft.WebpImageExtension',
		'Microsoft.DolbyAudioExtensions',
		# 'Microsoft.AVCEncoderVideoExtension',
		'Microsoft.MPEG2VideoExtension',

		### Surface Hub Apps / Team edition
		'Microsoft.Whiteboard',
		'microsoft.microsoftskydrive',
		'Microsoft.MicrosoftTeamsforSurfaceHub',
		'MicrosoftCorporationII.MailforSurfaceHub',
		'Microsoft.MicrosoftPowerBIForWindows',
		'Microsoft.SkypeApp',
		'Microsoft.Office.Excel',
		'Microsoft.Office.PowerPoint',
		'Microsoft.Office.Word',

		### Custom apps to keep/remove
		'Microsoft.MixedReality.Portal',
		'Microsoft.MSPaint', # Paint 3D
		'Microsoft.Office.OneNote',
		'Microsoft.MicrosoftPCManager'
	)

	$output = & dism /English /Image:"$wimMountPoint" /Get-ProvisionedAppxPackages
	$matcher = $output | Select-String "PackageName : (\S+)$"
	$packages = @()
	foreach ($match in $matcher.matches) {
		if ($match.groups.Count -ge 2) {
			$packages += $match.groups[1].Value
		}
	}
	$packagesToRemove = $packages | Where-Object {
		$packageName = $_
		$packagePrefixes -contains ($packagePrefixes | Where-Object { $packageName -like "$_*" })
	}

	foreach ($package in $packagesToRemove) {
		Tiny11-TtyPrint -NoNewLine -EraseLine "Removing package: $package"
		$errOutput = & dism /English /Image:"$wimMountPoint" /Remove-ProvisionedAppxPackage /PackageName:"$package" 2>&1
		if ($LastExitCode -ne 0) {
			Write-Output $errOutput
		}
	}
	if ($packagesToRemove.Count -ge 1) { Write-Host }
}

function Tiny11-RemoveEdgeWebBrowser {
	if (!$RemoveEdgeWebBrowser) { return }

	Tiny11-TtyPrint 'Removing Microsoft Edge and Edge WebView...'
	$edgeDirNames = @('Edge', 'EdgeCore', 'EdgeUpdate', 'EdgeWebView')
	foreach ($dirName in $edgeDirNames) {
		Remove-Item -Path "$wimMountPoint\Program Files (x86)\Microsoft\$dirName" -Recurse -Force 2>&1 | Out-Null
	}

	$isa = Tiny11-ReadWimISA "$workingDir\sources\install.wim" $ImageOrdinal
	$webviewDir = $Null
	if ('amd64' -eq $isa) {
		$webviewDir = 'amd64'
	} elseif ('arm64' -eq $isa) {
		$webviewDir = 'arm64'
	}
	if ($webviewDir) {
		$webviewDir = "$($webviewDir)_microsoft-edge-webview_*"
		$webviewDir = Get-ChildItem -Path "$wimMountPoint\Windows\WinSxS" -Filter $webviewDir -Directory | Select-Object -ExpandProperty FullName
	}
	if ($webviewDir) {
		& takeown /f $webviewDir /r 2>&1 | Out-Null
		& icacls $webviewDir  /grant "$($theAdminGroup.Value):(F)" /T /C 2>&1 | Out-Null
	}

	& takeown /f "$wimMountPoint\Windows\System32\Microsoft-Edge-Webview" /r 2>&1 | Out-Null
	& icacls "$wimMountPoint\Windows\System32\Microsoft-Edge-Webview" /grant "$($theAdminGroup.Value):(F)" /T /C 2>&1 | Out-Null
	Remove-Item -Path "$wimMountPoint\Windows\System32\Microsoft-Edge-Webview" -Recurse -Force 2>&1 | Out-Null
}

function Tiny11-ReadWimISA {
	param(
		[Parameter(Mandatory=$True)]
		[string]$wimFilePath,
		[Parameter(Mandatory=$True)]
		[int]$ordinal
	)

	$output = & dism /English /Get-WimInfo /WimFile:$wimFilePath /Index:$ordinal
	$matcher = $output | Select-String "Architecture : (\S+)$"
	if ($matcher.matches.Count -eq 0 -and $matcher.matches.groups.Count -le 1) {
		return $Null
	}
	$isa = $matcher.matches.groups[1]
	if ('x64' -eq $isa) {
		$isa = 'amd64'
	}
	return $isa
}

function Tiny11-RemoveOneDrive {
	Tiny11-TtyPrint 'Removing OneDrive...'
	& takeown /f "$wimMountPoint\Windows\System32\OneDriveSetup.exe" 2>&1 | Out-Null
	& icacls "$wimMountPoint\Windows\System32\OneDriveSetup.exe" /grant "$($adminGroup.Value):(F)" /T /C 2>&1 | Out-Null
	Remove-Item -Path "$wimMountPoint\Windows\System32\OneDriveSetup.exe" -Force 2>&1 | Out-Null
	Remove-Item -Path "$wimMountPoint\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" 2>&1 | Out-Null
}

function Tiny11-ApplyRegistryOptimizations {
	Tiny11-TtyPrint 'Running registry optimizaitons...'
	& reg load 'HKLM\zCOMPONENTS' "$wimMountPoint\Windows\System32\config\COMPONENTS" 2>&1 | Out-Null
	& reg load 'HKLM\zDEFAULT' "$wimMountPoint\Windows\System32\config\DEFAULT" 2>&1 | Out-Null
	& reg load 'HKLM\zNTUSER' "$wimMountPoint\Users\Default\NTUSER.DAT" 2>&1 | Out-Null
	& reg load 'HKLM\zSOFTWARE' "$wimMountPoint\Windows\System32\config\SOFTWARE" 2>&1 | Out-Null
	& reg load 'HKLM\zSYSTEM' "$wimMountPoint\Windows\System32\config\SYSTEM" 2>&1 | Out-Null

	Tiny11-TtyPrint -NoNewLine -EraseLine 'Bypassing system requirement checks(on the system image)...'
	& reg add 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV1' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV2' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV1' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV2' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassCPUCheck' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassRAMCheck' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassSecureBootCheck' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassStorageCheck' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassTPMCheck' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSYSTEM\Setup\MoSetup' /v 'AllowUpgradesWithUnsupportedTPMOrCPU' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null

	Tiny11-TtyPrint -NoNewLine -EraseLine 'Disabling sponsored apps...'
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableWindowsConsumerFeatures' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableConsumerAccountStateContent' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableCloudOptimizedContent' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'ContentDeliveryAllowed' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'FeatureManagementEnabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'OemPreInstalledAppsEnabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'PreInstalledAppsEnabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'PreInstalledAppsEverEnabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SilentInstalledAppsEnabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SoftLandingEnabled' /t 'REG_DWORD' /d '0' '/f'| Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContentEnabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContent-310093Enabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContent-338388Enabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContent-338389Enabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContent-338393Enabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContent-353694Enabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContent-353696Enabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SystemPaneSuggestionsEnabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start' /v 'ConfigureStartPins' /t 'REG_SZ' /d '{"pinnedList": [{}]}' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\PushToInstall' /v 'DisablePushToInstall' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\MRT' /v 'DontOfferThroughWUAU' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg delete 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions' /f 2>&1 | Out-Null
	& reg delete 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps' /f 2>&1 | Out-Null

	Tiny11-TtyPrint -NoNewLine -EraseLine 'Enabling Local Accounts on OOBE...'
	& reg add 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' /v 'BypassNRO' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	Copy-Item -Path "$PSScriptRoot\autounattend.xml" -Destination "$wimMountPoint\Windows\System32\Sysprep\autounattend.xml" -Force 2>&1 | Out-Null

	Tiny11-TtyPrint -NoNewLine -EraseLine 'Disabling Reserved Storage...'
	& reg add 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' /v 'ShippedWithReserves' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null

	Tiny11-TtyPrint -NoNewLine -EraseLine 'Disabling Windows Chat(Microsoft Teams)...'
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' /v 'ChatIcon' /t 'REG_DWORD' /d '3' /f 2>&1 | Out-Null
	& reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v 'ConfigureChatAutoInstall' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'TaskbarMn' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null

	Tiny11-TtyPrint -NoNewLine -EraseLine 'Removing Microsoft Edge related registries...'
	& reg delete 'HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge' /f 2>&1 | Out-Null
	& reg delete 'HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update' /f 2>&1 | Out-Null

	Tiny11-TtyPrint -NoNewLine -EraseLine 'Disabling OneDrive folder backup...'
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive' /v 'DisableFileSyncNGSC' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null

	Tiny11-TtyPrint -NoNewLine -EraseLine 'Disabling Telemetry...'
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' /v 'Enabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Privacy' /v 'TailoredExperiencesWithDiagnosticDataEnabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' /v 'HasAccepted' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Input\TIPC' /v 'Enabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' /v 'RestrictImplicitInkCollection' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' /v 'RestrictImplicitTextCollection' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization\TrainedDataStore' /v 'HarvestContacts' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Personalization\Settings' /v 'AcceptedPrivacyPolicy' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection' /v 'AllowTelemetry' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSYSTEM\ControlSet001\Services\dmwappushservice' /v 'Start' /t 'REG_DWORD' /d '4' /f 2>&1 | Out-Null

	Tiny11-TtyPrint -NoNewLine -EraseLine 'Disabling Cortana for Windows 10...'
	# This effectively skips Cortana setup on OOBE.
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search' /v 'AllowCortana' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null

	if ($RemoveEdgeWebBrowser) {
		Tiny11-TtyPrint -NoNewLine -EraseLine 'Cleaning Edge Browser registries...'
		# Registry keys are removed so the user could install Edge if they wish to.
		& reg delete 'HKLM\zSOFTWARE\Microsoft\EdgeUpdate' /f 2>&1 | Out-Null
		& reg delete 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge' /f 2>&1 | Out-Null
		& reg delete 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update' /f 2>&1 | Out-Null
		& reg delete 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView' /f 2>&1 | Out-Null
		& reg delete 'HKLM\zSOFTWARE\WOW6432Node\Microsoft\EdgeUpdate' /f 2>&1 | Out-Null
		& reg delete 'HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge' /f 2>&1 | Out-Null
		& reg delete 'HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update' /f 2>&1 | Out-Null
		& reg delete 'HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView' /f 2>&1 | Out-Null
		& reg delete 'HKLM\zNTUSER\Software\Microsoft\EdgeUpdate' /f 2>&1 | Out-Null
		# The folloing registry keys aren't strictly necessary to remove, but this script did it anyways.
		& reg delete 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\EdgeUpdate' /f 2>&1 | Out-Null
		& reg delete 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\EdgeUpdate' /f 2>&1 | Out-Null
		& reg delete 'HKLM\zSYSTEM\ControlSet001\Services\edgeupdate' /f 2>&1 | Out-Null
		& reg delete 'HKLM\zSYSTEM\ControlSet001\Services\edgeupdatem' /f 2>&1 | Out-Null
		& reg delete 'HKLM\zSYSTEM\CurrentControlSet\Services\edgeupdate' /f 2>&1 | Out-Null
		& reg delete 'HKLM\zSYSTEM\CurrentControlSet\Services\edgeupdatem' /f 2>&1 | Out-Null
	}

	Tiny11-ApplyPersonalRegistryOptimizations

	Tiny11-ProcessEnablePrivilege SeTakeOwnershipPrivilege 2>&1 | Out-Null

	Tiny11-TtyPrint -NoNewLine -EraseLine "Taking ownership of registry 'HLCM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks'..."
	$regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks',[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::TakeOwnership)
	$regACL = $regKey.GetAccessControl()
	$regACL.SetOwner($theAdminGroup)
	$regKey.SetAccessControl($regACL)
	$regKey.Close()
	$regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks',[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions)
	$regACL = $regKey.GetAccessControl()
	$regRule = New-Object System.Security.AccessControl.RegistryAccessRule($theAdminGroup, 'FullControl', 'ContainerInherit', 'None', 'Allow')
	$regACL.SetAccessRule($regRule)
	$regKey.SetAccessControl($regACL)
	$regKey.Close()

	Tiny11-TtyPrint -NoNewLine -EraseLine 'Deleting Application Compatibility Appraiser'
	& reg delete 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}' /f 2>&1 | Out-Null

	Tiny11-TtyPrint -NoNewLine -EraseLine 'Deleting Customer Experience Improvement Program'
	& reg delete 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}' /f 2>&1 | Out-Null
	& reg delete 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}' /f 2>&1 | Out-Null
	& reg delete 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}' /f 2>&1 | Out-Null

	Tiny11-TtyPrint -NoNewLine -EraseLine 'Deleting Program Data Updater'
	& reg delete 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}' /f 2>&1 | Out-Null

	Tiny11-TtyPrint -NoNewLine -EraseLine 'Deleting autochk proxy'
	& reg delete 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{87BF85F4-2CE1-4160-96EA-52F554AA28A2}' /f 2>&1 | Out-Null
	& reg delete 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8A9C643C-3D74-4099-B6BD-9C6D170898B1}' /f 2>&1 | Out-Null

	Tiny11-TtyPrint -NoNewLine -EraseLine 'Deleting QueueReporting'
	& reg delete 'HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E3176A65-4E44-4ED3-AA73-3283660ACB9C}' /f 2>&1 | Out-Null

	if ($DisableWinDef) {
		Tiny11-TtyPrint -NoNewLine -EraseLine 'Disabling Windows Defender...'
		# Disable Windows Defender services so it can't be turned on in Windows Defender Settings app.
		$serviceNames = @('WinDefend', 'WdNisSvc', 'WdNisDrv', 'WdFilter', 'Sense')
		foreach ($svcName in $serviceNames) {
			& reg add "HKLM\zSYSTEM\ControlSet001\Services\$svcName" /v 'Start' /t 'REG_DWORD' /d '4' /f 2>&1 | Out-Null
		}

		# Turn off notifications from Windows Defender.
		& reg delete 'HKLM\zSOFTWARE\Microsoft\Windows Defender Security Center\Notifications\DisableNotifications' /f 2>&1 | Out-Null
		& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' /v 'DisableNotifications' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null

		# Disable SmartScreen
		& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\System' /v 'EnableSmartScreen' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
		& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WTDS\Components' /v 'ServiceEnabled' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	}

	Write-Host
	Tiny11-TtyPrint 'Unmounting Registry...'
	& reg unload 'HKLM\zCOMPONENTS' 2>&1 | Out-Null
	& reg unload 'HKLM\zDEFAULT' 2>&1 | Out-Null
	& reg unload 'HKLM\zNTUSER' 2>&1 | Out-Null
	& reg unload 'HKLM\zSOFTWARE' 2>&1 | Out-Null
	& reg unload 'HKLM\zSYSTEM' 2>&1 | Out-Null
}

function Tiny11-ApplyPersonalRegistryOptimizations {
	Tiny11-TtyPrint -NoNewLine -EraseLine 'Applying per-user tweaks...'

	# Hides Microsoft Meet Now taskbar icon.
	& reg add 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'HideSCAMeetNow' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	# Disables News and Interests on Taskbar.
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Feeds' /v 'ShellFeedsTaskbarViewMode' /t 'REG_DWORD' /d '2' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Feeds' /v 'HeadlinesOnboardingComplete' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	# Sets Taskbar alignment to left.
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'TaskbarAl' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	# Don't prettify file name when editing file name in Explorer.
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'DontPrettyPath' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	# Hides "Task view" button on Taskbar.
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ShowTaskViewButton' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	# Sets "Open File Explorer to" to "This PC".
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'LaunchTo' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	# Hides search box on Taskbar.
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Search' /v 'SearchboxTaskbarMode' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	# Disables show desktop at the far corner of the Taskbar.
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'TaskbarSd' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	# Show Taskbar on all displays.
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'MMTaskbarEnabled' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	# Disables Auto Play.
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoDriveTypeAutoRun' /t 'REG_DWORD' /d '255' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoAutorun' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Policies\Microsoft\Windows\Explorer' /v 'NoAutoplayfornonVolume' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'NoAutoplayfornonVolume' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	# Disables Copilot on Windows 11.
	& reg add 'HKLM\zNTUSER\Software\Policies\Microsoft\Windows\WindowsCopilot' /v 'TurnOffWindowsCopilot' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	# Disables automatic Windows update, also defer updates other than security updates up to 1 year.
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'NoAutoUpdate' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'AUOptions' /t 'REG_DWORD' /d '2' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdates' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdatesPeriodInDays' /t 'REG_DWORD' /d '365' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdates' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdatesPeriodInDays' /t 'REG_DWORD' /d '365' /f 2>&1 | Out-Null
	# Disable driver updates in Windows Update.
	# & reg add 'HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Update' /v 'ExcludeWUDriversInQualityUpdate' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	# & reg add 'HKLM\zSOFTWARE\Microsoft\PolicyManager\default\Update' /v 'ExcludeWUDriversInQualityUpdate' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	# & reg add 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'ExcludeWUDriversInQualityUpdate' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	# & reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'ExcludeWUDriversInQualityUpdate' /t 'REG_DWORD' /d '1' 2>&1 | Out-Null
	# & reg add 'HKLM\zSOFTWARE\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdate' /v 'value' /d '1' /f 2>&1 | Out-Null
	# Remove "Recommended" section from Start Menu.
	& reg delete 'HKLM\zNTUSER\Software\Policies\Microsoft\Windows\Explorer\HideRecommendedSection' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer\' /v 'HideRecommendedSection' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	# Prevent Outlook from automatically installed.
	& reg add 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate' /v 'workCompleted' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg delete 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate' /f 2>&1 | Out-Null
	# Prevent DevHome from automatically installed.
	& reg add 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate' /v 'workCompleted' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg delete 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate' /f 2>&1 | Out-Null
	# Prevent MicrosoftPCManager from automatically installed.
	& reg add 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\PCManagerUpdate' /v 'workCompleted' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg delete 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\PCManagerUpdate' /f 2>&1 | Out-Null

	<#
	# "This PC -> Advanced system settings -> 'Advanced' tab -> Performance settings"
	# Turns out these settings have different value on different versions of Windows.
	# Turns off "Animate controls and elements inside windows"
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' /v "VisualFXSetting" /t 'REG_DWORD' /d '3' /f 2>&1 | Out-Null
	# Turns off "Animate windows when minimizing and maximizing"
	& reg add 'HKLM\zNTUSER\Control Panel\Desktop\WindowMetrics' /v 'MinAnimate' /t 'REG_SZ' /d '0' /f 2>&1 | Out-Null
	# Disable "Animations in Taskbar and Start Menu"
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'TaskbarAnimations' /t 'REG_SZ' /d '0' /f 2>&1 | Out-Null
	# Disable "Aero Peek"
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\DWM' /v 'EnableAeroPeek' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	# Disable "Save taskbar thumbnail previews"
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\DWM' /v 'AlwaysHibernateThumbnails' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	# Enable "Show thumbnails instead of icons"
	& reg add 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'DisableThumbnails' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'DisableThumbnails' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	# Enable "Show translucent selection rectangle"
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ListviewAlphaSelect' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	# Enable "Show window contents while dragging"
	& reg add 'HKLM\zNTUSER\Control Panel\Desktop' /v 'DragFullWindows' /t 'REG_SZ' /d '1' /f 2>&1 | Out-Null
	# Enable "Smooth edges of Screen Fonts"
	& reg add 'HKLM\zNTUSER\Control Panel\Desktop' /v 'FontSmoothing' /t 'REG_SZ' /d '1' /f 2>&1 | Out-Null
	# Use drop shadows for icon labels on the desktop
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ListviewShadow' /t 'REG_SZ' /d '1' /f 2>&1 | Out-Null
	# (N) Smooth-scroll list boxes
	# (N) Slide open combo boxes
	# (N) Fade or slide menus into view
	# (Y) Show shadows under mouse pointer
	# (N) Fade or slide ToolTips into view
	# (N) Fade out menu items after clicking
	# (N) Show shadows under windows
	& reg add 'HKLM\zNTUSER\Control Panel\Desktop' /v 'UserPreferencesMask' /t 'REG_BINARY' /d 'hex:90,32,03,80,10,00,00,00' /f 2>&1 | Out-Null
	#>

	# Tweaks copied from Zone94's Windows Integral Edition.
	# Disables the Diagnostic Data Collection (Privacy Setting).
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack' /v 'ShowedToastAtLevel' /t 'REG_DWORD' /d '0x0' /f 2>&1 | Out-Null
	# Sets the Feedback Frequency option to "Never" (Privacy Setting).
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Siuf\Rules' /v 'NumberOfSIUFInPeriod" /t 'REG_DWORD /d '0x0' /f 2>&1 | Out-Null
	# Displays the Hidden Files and Folders.
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'Hidden' /t 'REG_DWORD' /d '0x1' /f 2>&1 | Out-Null
	# Displays all the File Extensions.
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'HideFileExt' /t 'REG_DWORD' /d '0x0' /f 2>&1 | Out-Null
	# Show "This PC" (My Computer) on the Desktop.
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' /v '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' /t 'REG_DWORD' /d '0x0' /f 2>&1 | Out-Null
	# Displays the detailed Copy/Move/Delete file progress dialog.
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager' /v 'EnthusiastMode' /t 'REG_DWORD' /d '0x1' /f 2>&1 | Out-Null
	# Sets the Combine taskbar buttons to "Never".
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'TaskbarGlomLevel' /t 'REG_DWORD' /d '0x2' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'MMTaskbarGlomLevel' /t 'REG_DWORD' /d '0x2' /f 2>&1 | Out-Null
	# Turns Off the Windows Theme Transparency effects.
	# & reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' /v 'EnableTransparency' /t 'REG_DWORD' /d '0x0' /f 2>&1 | Out-Null
	# Turns On the Windows Theme accent color for Start menu, Taskbar, and Action center.
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' /v 'ColorPrevalence' /t 'REG_DWORD' /d '0x1' /f 2>&1 | Out-Null
	# Turns On the Windows Theme accent color for Title bars.
	& reg add 'HKLM\zNTUSER\Software\Microsoft\Windows\DWM' /v 'ColorPrevalence' /t 'REG_DWORD' /d '0x1' /f 2>&1 | Out-Null
	# Disabling OneDrive Auto Installation
	& reg delete 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Run' /v 'OneDriveSetup' /f 2>&1 | Out-Null

	# Tweaks copied from 'https://github.com/memstechtips/UnattendedWinstall/blob/main/autounattend.xml'.
	# Enables long file path support, currently it's disabled because it crashes the Windows setup process.
	# & reg add 'HKLM\zSYSTEM\CurrentControlSet\Control\FileSystem' /v 'LongPathsEnabled' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	# Disables Activity History.
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\System' /v 'EnableActivityFeed' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\System' /v 'PublishUserActivities' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\System' /v 'UploadUserActivities' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	# Disables Advertising ID for all users.
	& reg add 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' /v 'DisabledByGroupPolicy' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
}

## this function allows PowerShell to take ownership of the Scheduled Tasks registry key from TrustedInstaller. Based on Jose Espitia's script.
function Tiny11-ProcessEnablePrivilege {
	param(
		[ValidateSet(
			"SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
			"SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
			"SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
			"SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
			"SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
			"SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
			"SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
			"SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
			"SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
			"SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
			"SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
	$Privilege,
	## The process on which to adjust the privilege. Defaults to the current process.
	$ProcessId = $pid,
	## Switch to disable the privilege, rather than enable it.
	[Switch] $Disable
 )
 $definition = @'
 using System;
 using System.Runtime.InteropServices;

 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }

  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
	tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
	tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

	$processHandle = (Get-Process -id $ProcessId).Handle
	# The class type 'AdjPriv' could exist because of previous script execution.
	if (-not ([System.Management.Automation.PSTypeName]'AdjPriv').Type) {
		Add-Type $definition
	}
	[AdjPriv]::EnablePrivilege($processHandle, $Privilege, $Disable)
}

function Tiny11-ImageCleanUpAndUnmountAndExport {
	Tiny11-TtyPrint 'Cleaning up image...'
	& dism /English /Image:"$wimMountPoint" /Cleanup-Image /StartComponentCleanup /ResetBase

	Tiny11-TtyPrint 'Unmounting image...'
	& dism /English /Unmount-Image /MountDir:"$wimMountPoint" /Commit

	Tiny11-TtyPrint 'Exporting image...'
	& dism /English /Export-Image /SourceImageFile:"$workingDir\sources\install.wim" /SourceIndex:$ImageOrdinal /DestinationImageFile:"$workingDir\sources\install-new.wim" /Compress:recovery
	Remove-Item -Path "$workingDir\sources\install.wim" -Force
	Rename-Item -Path "$workingDir\sources\install-new.wim" -NewName "$workingDir\sources\install.wim"
}

function Tiny11-BypassingSystemRequirementsOnSetupImage {
	Tiny11-TtyPrint 'Mounting boot image...'
	$wimFilePath = "$workingDir\sources\boot.wim"
	& takeown /f $wimFilePath | Out-Null
	& icacls $wimFilePath /grant "$($adminGroup.Value):(F)" | Out-Null
	Set-ItemProperty -Path $wimFilePath -Name IsReadOnly -Value $False
	& dism /English /Mount-Image /ImageFile:"$workingDir\sources\boot.wim" /Index:2 /MountDir:$wimMountPoint

	Tiny11-TtyPrint 'Loading registry...'
	& reg load 'HKLM\zCOMPONENTS' "$wimMountPoint\Windows\System32\config\COMPONENTS" 2>&1 | Out-Null
	& reg load 'HKLM\zDEFAULT' "$wimMountPoint\Windows\System32\config\DEFAULT" 2>&1 | Out-Null
	& reg load 'HKLM\zNTUSER' "$wimMountPoint\Users\Default\NTUSER.DAT" 2>&1 | Out-Null
	& reg load 'HKLM\zSOFTWARE' "$wimMountPoint\Windows\System32\config\SOFTWARE" 2>&1 | Out-Null
	& reg load 'HKLM\zSYSTEM' "$wimMountPoint\Windows\System32\config\SYSTEM" 2>&1 | Out-Null

	Tiny11-TtyPrint 'Bypassing system requirements(on the setup image)...'
	& reg add 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV1' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV2' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV1' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV2' /t 'REG_DWORD' /d '0' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassCPUCheck' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassRAMCheck' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassSecureBootCheck' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassStorageCheck' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassTPMCheck' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null
	& reg add 'HKLM\zSYSTEM\Setup\MoSetup' /v 'AllowUpgradesWithUnsupportedTPMOrCPU' /t 'REG_DWORD' /d '1' /f 2>&1 | Out-Null

	Tiny11-TtyPrint 'Unmounting Registry...'
	& reg unload 'HKLM\zCOMPONENTS' 2>&1 | Out-Null
	& reg unload 'HKLM\zDEFAULT' 2>&1 | Out-Null
	& reg unload 'HKLM\zNTUSER' 2>&1 | Out-Null
	& reg unload 'HKLM\zSOFTWARE' 2>&1 | Out-Null
	& reg unload 'HKLM\zSYSTEM' 2>&1 | Out-Null

	Tiny11-TtyPrint 'Unmounting image...'
	& dism /English /Unmount-Image /MountDir:"$wimMountPoint" /Commit

	Tiny11-TtyPrint 'Copying unattended file for bypassing MS account on OOBE...'
	Copy-Item -Path "$PSScriptRoot\autounattend.xml" -Destination "$workingDir\autounattend.xml" -Force 2>&1 | Out-Null
}

function Tiny11-CreateBootableISO {
	Tiny11-TtyPrint 'Creating bootable Windows installation ISO...'
	& "$PSScriptRoot\oscdimg.exe" '-m' '-o' '-u2' '-udfver102' '-g' '-lTiny11' "-bootdata:2#p0,e,b$workingDir\boot\etfsboot.com#pEF,e,b$workingDir\efi\microsoft\boot\efisys.bin" "$workingDir" "$PSScriptRoot\tiny11.iso"
}

function Tiny11-ScratchDirCleanUp {
	Tiny11-TtyPrint 'Cleaning up scratch directory...'

	reg unload 'HKLM\zCOMPONENTS' 2>&1 | Out-Null
	reg unload 'HKLM\zDRIVERS' 2>&1 | Out-Null
	reg unload 'HKLM\zDEFAULT' 2>&1 | Out-Null
	reg unload 'HKLM\zNTUSER' 2>&1 | Out-Null
	reg unload 'HKLM\zSCHEMA' 2>&1 | Out-Null
	reg unload 'HKLM\zSOFTWARE' 2>&1 | Out-Null
	reg unload 'HKLM\zSYSTEM' 2>&1 | Out-Null
	& dism /English /Unmount-Image /MountDir:"$wimMountPoint" /Discard 2>&1 | Out-Null
	Remove-Item -Path "$wimMountPoint" -Recurse -Force 2>&1 | Out-Null

	Remove-Item -Path "$workingDir" -Recurse -Force 2>&1 | Out-Null
}

function Tiny11-TtyPrint {
	param(
		[Parameter()][switch]$NoNewLine = $False,
		[Parameter()][switch]$EraseLine = $False,
		$text = ""
	)

	if ($EraseLine) {
		$width = $Host.UI.RawUI.BufferSize.Width
		$erase = "`r" + $(' ' * $width) + "`r"
		Write-Host -NoNewLine $erase
	}

	Write-Host -NoNewLine '['
	Write-Host -NoNewLine -ForegroundColor Green 'Tiny11'
	Write-Host -NoNewLine '] '
	Write-Host -NoNewLine $text

	if (!$NoNewLine) { Write-Host }
	[Console]::Out.Flush()
}

Tiny11-Main
exit
