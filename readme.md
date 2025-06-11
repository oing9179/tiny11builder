# Tiny11 but tailored for my personal taste

In addition to the original Tiny11, this modified script has more agressive
tweaks, including:

- Works for both Windows 11 x86_64 and aarch64 and Windows 10 x86_64.
- Ability to disable Windows Defender.
- Ability to remove the Edge Browser.
- Most of the bloatwares are removed.
- Language selection and local account creation are the only 2 steps shown on OOBE.
- A slightly modified `autounattended.xml` file generated from [the generator](https://schneegans.de/windows/unattend-generator/).
- Disables Windows Recall.

## Usage

For noobs, in file explorer right click on the script file then click "Run with PowerShell", same as the original Tiny11
creator.

For pros, open PowerShell with Admin privilege, then run the script, here are the command line args you can pass to the
script:

```powershell
# The script read settings from command line args instead of from stdin interactively.
-NonInteractive

# The drive letter where the Windows installation ISO is mounted. Required for NonInteractive mode.
-DriveLetter <string>

# The ordinal(or index) of the Windows installation image, see "dism.exe /Get-WimInfo". Required for NonInteractive mode.
-ImageOrdinal <integer>

# The directory to store temporary files, defaults to "$Env:Temp".
-ScratchDir <path>

# Removes the Edge Browser including Edge WebView, it can be reinstalled later on.
-RemoveEdgeWebBrowser

# Disables Winows Defender including SmartScreen, can be re-enabled by tweaking the Windows registry.
-DisableWinDef

# Don't clean the scratch dir.
-SkipCleanUp

# Clean the scratch dir then exit.
-PerformCleanUp
```

There are some tweaks disabled(commented out) because of potential unforeseeable bugs.

## Re-enable Windows Defender and SmartScreen

Create a file with whatever name with file extension `.reg`, then paste the following content into
the `.reg` file:

```
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WinDefend]
"Start"=-

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WdNisSvc]
"Start"=-

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WdNisDrv]
"Start"=-

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WdFilter]
"Start"=-

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sense]
"Start"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications]
"DisableNotifications"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"EnableSmartScreen"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components]
"ServiceEnabled"=-
```

Then import this `.reg` file using Registry Editor `regedit.exe`.
