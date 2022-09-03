# xai_plugin
[XAI Plugin - Original Source by mysis](https://www.psx-place.com/threads/custom-xai_plugin-source.12455/)

Remember that videorec.sprx and xai_plugin.sprx must be signed after compiled

This version of xai_plugin was modified to be used on **CFW 4.88 Evilnat** and **CFW 4.88.2 Evilnat**


### Files that need to be modified (XMB/XAI strings)

* **explore_plugin_full.rco**
* **xai_plugin.rco**

These files must contain proper strings lines so they can appear in the XMB

The format is the following:

```
<Text name="string_name">Here goes your text line</Text>
```

For example:

```
<Text name="msg_net">Network</Text>
```


### Options added in xai_plugin

```
• Turn Off: Turns off the PS3
• Hard Reboot: Reboots the PS3 completely
• Soft Reboot: Reboots the PS3 softly
• Reboot LV2: Reboots the LV2

• FAN Speed: Shows current FAN speed
• PS3 Temperature: Shows current CPU and RSX temperature
• Show IDPS: Shows current IDPS
• Show PSID: Shows current PSID
• Toggle Coldboot: Toggles between custom/original coldboot.raf
• Toggle System Version: Toggles between custom/original system version in "System Information"

• Show accountID: Shows current user's accountID
• Backup activation file: Creates a backup of act.dat to /dev_usb or /dev_hdd0
• Disable account: Deletes current user's activation file act.dat permanently
• Backup xRegistry.sys: Creates a backup of xRegistry.sys to /dev_usb or /dev_hdd0
• Button Assignment: Switches O and X buttons

• Convert savedata: Converts savedata from "/dev_usbXXX/PS3/SAVEDATA" to your own savedata
• Cobra Information: Shows current Cobra information
• Activate account: Creates act.dat file in the current local account
• Create license: Creates RIF licenses from RAP files from "x:\exdata"
• Create accountID: Creates a fake accountID for current user's in xRegistry
• Overwrite accountID: Overwrites current user's accountID with a fake one in xRegistry
• Create Syscalls: Create syscalls 6, 7, 8, 9, 10, 11, 15, 389 and 409
• Allow Restore Syscalls: Allows restoring syscalls through "System Update"
• Skip license creation: Skips overwriting license file (RIF) if it already exists
• Toggle Cobra: Enables or disables Cobra (reboot is required)
• Toggle Cobra Version: Toggles between release and debug versions (reboot is required)

• Control FAN Mode: DISABLED: Disables Cobra’s Control FAN
• Control FAN Mode: SYSCON: Allows the PS3's SYSCON to control FAN speed
• Control FAN Mode: MAX: Set Cobra FAN speed to 0xFF

• Check QA Flags: Check if QA flags are enabled or disabled
• Enable QA Flags: Enables QA Flags
• Disable QA Flags: Disables QA Flags

• Maximum temperature: 60°C: Sets the FAN speed dynamically to keep the system at a maximum temperature of 60°C
• Maximum Temperature: 65°C: Sets the FAN speed dynamically to keep the system at a maximum temperature of 65°C
• Maximum Temperature: 70°C: Sets the FAN speed dynamically to keep the system at a maximum temperature of 70°C
• Maximum Temperature: 75°C: Sets the FAN speed dynamically to keep the system at a maximum temperature of 75°C

• Manual Speed: 40%: Sets the FAN speed statically at 40% (0x67)
• Manual Speed: 45%: Sets the FAN speed statically at 45% (0x75)
• Manual Speed: 50%: Sets the FAN speed statically at 50% (0x80)
• Manual Speed: 55%: Sets the FAN speed statically at 55% (0x8E)
• Manual Speed: 60%: Sets the FAN speed statically at 60% (0x9B)
• Manual Speed: 65%: Sets the FAN speed statically at 65% (0xA8)
• Manual Speed: 70%: Sets the FAN speed statically at 70% (0xB5)
• Manual Speed: 75%: Sets the FAN speed statically at 75% (0xC0)
• Manual Speed: 80%: Sets the FAN speed statically at 80% (0xCE)
• Manual Speed: 85%: Sets the FAN speed statically at 85% (0xDA)
• Manual Speed: 90%: Sets the FAN speed statically at 90% (0xE7)
• Manual Speed: 95%: Sets the FAN speed statically at 95% (0xF4)

• PS2 FAN Mode: DISABLED: Disables Control FAN on PS2 game
• PS2 FAN Mode: SYSCON: Allows the PS3's SYSCON to control FAN speed on PS2 game
• PS2 FAN Mode: 40%: Sets FAN speed to 0x66 on PS2 game
• PS2 FAN Mode: 50%: Sets FAN speed to 0x80 on PS2 game
• PS2 FAN Mode: 60%: Sets FAN speed to 0x9A on PS2 game
• PS2 FAN Mode: 70%: Sets FAN speed to 0xB4 on PS2 game
• PS2 FAN Mode: 80%: Sets FAN speed to 0xCE on PS2 game
• PS2 FAN Mode: 90%: Sets FAN speed to 0xE8 on PS2 game

• View Log: http://localhost/dev_hdd0/tmp/cfw_settings.log (webMAN MOD is required for this function)
• Clean Log File: Resets /dev_hdd0/tmp/cfw_settings.log file
• Dump IDPS: Saves IDPS to log file
• Dump PSID: Saves PSID to log file
• Dump LV2: Dumps LV2 to /dev_usb or /dev_hdd0/tmp
• Dump LV1: Dumps LV1 to /dev_usb or /dev_hdd0/tmp
• Dump ERK: Dumps eid_root_key to /dev_usb or /dev_hdd0/tmp
• Log KLicense usage: Saves filename and klicensee to log file
• Log Secure File ID usage: Writes save data name and file ID key to log file
• Dump Disc Hash Key: Retrieves disc hash key from an ORIGINAL game disc
```
