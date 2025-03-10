# xai_plugin
XAI Plugin - Original Source by mysis [https://www.psx-place.com/threads/custom-xai_plugin-source.12455/]

Remember that videorec.sprx and xai_plugin.sprx must be signed after compiled

This version of xai_plugin was modified to be used on **CFW 4.92 Evilnat**

Repositories used:
[sguerrini97's setup_flash_for_otheros](https://github.com/sguerrini97/psl1ghtv2_ports/tree/master/setup_flash_for_otheros)
[sguerrini97's get_token_seed](https://github.com/sguerrini97/psl1ghtv2_ports/tree/master/get_token_seed)
[sguerrini97's dump_sysrom](https://github.com/sguerrini97/psl1ghtv2_ports/tree/master/dump_sysrom/source)
[sguerrini97's setup_flash_for_otheros](https://github.com/sguerrini97/psl1ghtv2_ports/tree/master/setup_flash_for_otheros)
[Rebug Toolbox](https://github.com/Joonie86/Rebug-Toolbox)
[flatz's EID root key dumper](https://github.com/Joonie86/erk_dumper)
[TheRouletteBoi's RouLetteVshMenu](https://github.com/TheRouletteBoi/RouLetteVshMenu)
[bucanero's ps3-advanced-toolset](https://github.com/bucanero/ps3-advanced-toolset/tree/master/sm_error_log)


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
Power Options
• Turn Off: Turns off the PS3
• Hard Reboot: Reboots the PS3 completely
• Soft Reboot: Reboots the PS3 softly
• Reboot LV2: Reboots the LV2

File Manager
• All Active Devices: Manage all active partitions
• Internal Hard Disk Drive 0: Manage PS3 files in /dev_hdd0
• Internal Hard Disk Drive 1: Manage PS3 cached files in /dev_hdd1
• USB Mass Storage Devices: Manage files on your USB devices
• Internal Flash Memory: Manage PS3 internal flash files
• Optical Disc: Manage optical discs
• Memory Cards: Manage memory cards

Basic Tools
• Decrypt 3k3y/Redump ISOs (HDD): Decrypts 3k33y/redump ISOs from dev_hdd0/PS3ISO with 'd1/disc' key file if it is available
• Decrypt 3k3y/Redump ISOs (USB): Decrypts 3k33y/redump ISOs from dev_usb/PS3ISO with 'd1/disc' key file if it is available
• Import Licenses to rap.bin: Imports rap licenses from /dev_hdd0/exdata or /dev_usb/exdata to rap.bin file
• Export Licenses from rap.bin: Exports rap licenses from rap.bin file to /dev_hdd0/exdata or /dev_usb/exdata
• Fix CBOMB: Patches RTC with static value (default) or current updated PS3 system date. Useful for PS3 with dead CMOS battery
• Show Total PS3 Usage: Shows the total days that the PS3 has been on, number of times it has been turned on and off
• FAN Speed: Shows current FAN speed
• PS3 Temperature: Shows current CPU and RSX temperature in Celsius and Fahrenheit
• Check GPU/VRAM clock speed: Checks current GPU/VRAM clock speed
• Show IDPS: Shows current IDPS
• Show PSID: Shows current PSID
• Show IP: Show current IP if it exists
• Toggle Coldboot: Toggles between custom/original coldboot.raf
• Toggle Third Party BT Headset: Enables or diasbles usage of third party BT headset
• Show BD Drive Information: Shows current BD Drive Information
• Show XAI Version: Shows the current version of xai_plugin

Basic Tools > xRegistry Tools
• Show Region Info: Shows current DVD TV mode and BDVD/DVD/PS3 region
• DVD TV System: Switch between PAL and NTSC for DVD Movies
• Backup xRegistry.sys: Creates a backup of xRegistry.sys to /dev_usb or /dev_hdd0
• Button Assignment: Switches O and X buttons

Basic Tools > xRegistry Tools > Region Tools
• Default/Disabled: Sets BDVD/DVD/PS3 region to Default in xRegistry (0x00)
• Japan: Sets BDVD/DVD/PS3 region to Japan in xRegistry (0x83)
• USA: Sets BDVD/DVD/PS3 region to USA in xRegistry (0x84)
• Europe: Sets BDVD/DVD/PS3 region to Europe in xRegistry (0x85)
• Korea: Sets BDVD/DVD/PS3 region to Korea in xRegistry (0x86)
• United Kingdom: Sets BDVD/DVD/PS3 region to United Kingdom in xRegistry (0x87)
• Mexico: Sets BDVD/DVD/PS3 region to Mexico in xRegistry (0x88)
• Australia: Sets BDVD/DVD/PS3 region to Australia in xRegistry (0x89)
• Asia: Sets BDVD/DVD/PS3 region to Asia in xRegistry (0x8A)
• Taiwan: Sets BDVD/DVD/PS3 region to Taiwan in xRegistry (0x8B)
• Russia: Sets BDVD/DVD/PS3 region to Russia in xRegistry (0x8C)
• China: Sets BDVD/DVD/PS3 region to China in xRegistry (0x8D)
• Hong Kong: Sets BDVD/DVD/PS3 region to Hong Kong in xRegistry (0x8E)
• Brazil: Sets BDVD/DVD/PS3 region to Brazil in xRegistry (0x8F)

Basic Tools > Led Tools
• Off: Turns off the PS3's power LED
• Red (Static): Sets the PS3's power LED to static red
• Green (Static): Sets the PS3's power LED to static green
• Yellow (Static): Sets the PS3's power LED to static yellow
• Red (Slow blink): Sets the PS3's power LED to slow blink red
• Green (Slow blink): Sets the PS3's power LED to slow blink green
• Yellow (Slow blink): Sets the PS3's power LED to slow blink yellow
• Red (Fast blink): Sets the PS3's power LED to fast blink red
• Green (Fast blink): Sets the PS3's power LED to fast blink green
• Yellow (Fast blink): Sets the PS3's power LED to fast blink yellow
• Yellow + Green (Fast blink): Sets the PS3's power LED to fast blink yellow + green
• Yellow + Red (Fast blink): Sets the PS3's power LED to fast blink yellow + red
• Yellow + Green (Slow blink): Sets the PS3's power LED to slow blink yellow + green
• Yellow + Red (Slow blink): Sets the PS3's power LED to slow blink yellow + red
• Rainbow Mode: Sets the PS3's power LED to rainbow mode
• Special Mode 1: Sets the PS3's power LED to special mode 1
• Special Mode 2: Sets the PS3's power LED to special mode 2

Basic Tools > Buzzer Tools
• Single Beep: Generates a single beep with the internal buzzer
• Double Beep: Generates a double beep with the internal buzzer
• Triple Beep: Generates a triple beep with the internal buzzer
• Continuous Beep: Generates a continuous beep with the internal buzzer

FAN Tools
• Control FAN Mode: DISABLED: Disables Cobra’s Control FAN
• Control FAN Mode: SYSCON: Allows the PS3's SYSCON to control FAN speed
• Control FAN Mode: MAX: Set Cobra FAN speed to 0xFF

FAN Tools > Dynamic FAN Control
• Maximum temperature: 60°C: Sets the FAN speed dynamically to keep the system at a maximum temperature of 60°C
• Maximum Temperature: 65°C: Sets the FAN speed dynamically to keep the system at a maximum temperature of 65°C
• Maximum Temperature: 70°C: Sets the FAN speed dynamically to keep the system at a maximum temperature of 70°C
• Maximum Temperature: 75°C: Sets the FAN speed dynamically to keep the system at a maximum temperature of 75°C

FAN Tools > Manual Speed
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
• Manual Speed: 95%: Sets the FAN speed statically at 90% (0xF4)

Cobra Tools > FAN Tools > PS2 FAN
• PS2 Fan Mode: DISABLED: Disables Control FAN on PS2 game
• PS2 Fan Mode: SYSCON: Allows the PS3's SYSCON to control FAN speed on PS2 game
• PS2 Fan Mode: 40%: Sets FAN speed to 0x66 on PS2 game
• PS2 Fan Mode: 50%: Sets FAN speed to 0x80 on PS2 game
• PS2 Fan Mode: 60%: Sets FAN speed to 0x9A on PS2 game
• PS2 Fan Mode: 70%: Sets FAN speed to 0xB4 on PS2 game
• PS2 Fan Mode: 80%: Sets FAN speed to 0xCE on PS2 game
• PS2 Fan Mode: 90%: Sets FAN speed to 0xE8 on PS2 game

QA Tools
• Enable QA Flags (Normal): Enables QA Flags through "Network Settings"
• Enable QA Flags (Advanced): Enables advanced QA Flags through "Network Settings"
• Disable QA Flags: Disables QA Flags through "Network Settings"

Cobra Tools
• Cobra Information: Shows current Cobra information
• Check Syscall 8: Checks Cobra's Syscall 8 status
• Create Syscalls: Create syscalls 6, 7, 8, 9, 10, 11, 15 and 35
• Toggle PSN Protection: Enables/blocks PSN login when syscalls are enabled
• Toggle TrophyUnlocker: Enables/disables TrophyUnlocker INGAME plugin
• Allow Restore Syscalls: Allows restoring syscalls through "System Update"
• Skip license creation: Skips overwriting license file (RIF) if it already exists
• Create license: Creates RIF licenses from RAP files from "x:\exdata"
• Toggle Plugins: Enables/disables Cobra plugins from /dev_hdd0/boot_plugins.txt
• Toggle OFW Mode on Boot: Toggles between CFW syscalls on boot enabled, disabled and partial
• Toggle PS2 Disc Icon: Toggles between default and blue PS3 disc icon in XMB
• Toggle Gameboot: Enables or disables original PLAYSTATION 3 gameboot when statring a game or application
• Toggle Hidden Trophy Info: Enables or disables hidden trophies title, details and icon in XMB/INGMAE
• Toggle Coldboot Animation: Enables or disables the coldboot animation and sound on boot
• Toggle Epilepsy Warning: Enables or disables epilepsy warning on boot
• Toggle Cobra Version: Toggles between release and debug versions (reboot is required)
• Toggle Cobra: Enables or disables Cobra (reboot is required)

PSN Tools
• Disable Syscalls: Disables syscalls and remove history files
• Spoof TargetID: Spoofs current TargetID in LV2 with EID5's TargetID
• Spoof IDPS: Spoofs IDPS in LV2 with a valid IDPS from "/dev_usb/IDPS.txt"
• Spoof PSID: Spoofs PSID in LV2 with a valid PSID from "/dev_usb/PSID.txt"
• Show accountID: Shows current user's accountID
• Create accountID: Creates a fake accountID for current user's in xRegistry
• Overwrite accountID: Overwrites current user's accountID with a fake one in xRegistry
• Activate account: Creates act.dat file in the current local account
• Create license: Creates RIF licenses from RAP files from "x:\exdata"
• Backup activation file: Creates a backup of act.dat to /dev_usb or /dev_hdd0
• Disable account: Deletes current user's activation file act.dat permanently
• Convert savedata: Converts savedata from "/dev_usbXXX/PS3/SAVEDATA" to your own savedata

Dump Tools
• View Log: http://localhost/dev_hdd0/tmp/cfw_settings.log (webMAN MOD is required for this function)
• Clean Log File: Resets /dev_hdd0/tmp/cfw_settings.log file
• Dump IDPS: Saves IDPS to log file
• Dump PSID: Saves PSID to log file
• Export RAP license: Exports the RAP license from the RIF licenses installed in the current user account in /dev_usb/exdata
• Dump LV2: Dumps LV2 to /dev_usb or /dev_hdd0/tmp
• Dump LV1: Dumps LV1 to /dev_usb or /dev_hdd0/tmp
• Dump Flash: Dumps NOR/NAND Flash to dev_hdd0/tmp or /dev_usb
• Dump RAM: Dumps RAM to /dev_usb or /dev_hdd0/tmp
• Dump SYSROM: Dumps SYSROM to /dev_usb or /dev_hdd0/tmp
• Dump EEPROM: Dumps 256 bytes of EEPROM data from offsets 0x2F00, 0x3000, 0x48000, 0x48800, 0x48C00 and 0x48D00 in /dev_usb or /dev_hdd0/tmp
• Dump ERK: Dumps eid_root_key to /dev_usb or /dev_hdd0/tmp
• Dump METLDR: Dumps decrypted metldr to /dev_usb or /dev_hdd0/tmp
• Dump SYSCON Error Log: Dumps current SYSCON error log in /dev_usb or /dev_hdd0/tmp
• Dump Token Seed: Dumps current token seed in /dev_usb or /dev_hdd0/tmp
• Log KLicense usage: Saves filename and klicensee to log file
• Log Secure File ID usage: Writes save data name and file ID key to log file
• Dump Disc Hash Key: Retrieves disc hash key from an ORIGINAL game disc

Rebug Tools
• LV1 Peek/Poke Support: Patch unused LV1 syscalls 182 and 183
• LV2 Memory Protection: Patch Shutdown on LV2 modification
• HTAB Mapping With Write Protection: Enable or Disable protected HTAB mapping
• Access to all INDI Info Manager Services: Enable or Disable INDI access
• Update Manager EEPROM Write Access: Patch Update Manager access to EEPROM
• Dispatch Manager Access: Patch Dispatch Manager access to all services
• Allow ENCDEC IOCTL Command 0x85: Enable IOCTL Command 0x85
• System Manager Ability Mask of GameOS: Allow access to all system manager services
• Extract all PKG Types: Allow Update Manager to extract all PKG types
• Full Access for Repo Nodes in Any LPAR: Allow create, modify, delete for repository nodes
• LV1 Full Access to MFC_SR1 SPE Register: Allow all-bit access to the register
• LV1 Access to set Data Break Points: Enable LV1 access with lv1_set_dabr()
• LV1 Access to GPU GART Memory: Allow LV1 to use 4KB IO page size
• Storage Manager ENCDEC Keys Access: Allow Storage Manager to clear ENCDEC keys
• Skip all ACL Checks: Enable skipping of ACL checks for all storage devices
• Initial GuestOS Loader: Enable GuestOS mode 1 for GameOS

OtherOS Tools
• Resize VFLASH/NAND Regions: Resizes VFLASH/NAND Regions 5 to allow OtherOS
• Install Petitboot: Installs Petitboot to VFLASH/NAND Regions 5 from USB device
• Set OtherOS Boot Flag: Reboots the PS3 and boot OtherOS
• Set GameOS Boot Flag: Fixes issues loading PS2 games when OtherOS boot flag is set

CEX2DEX Tools
• Convert to CEX: Converts PS3 to CEX/RETAIL with eid_root_key from /dev_usb or /dev_hdd0
• Convert to DEX: Converts PS3 to DEX/DEBUG with eid_root_key from /dev_usb or /dev_hdd0
• Swap Kernel: Swaps between CEX and DEX Kernels
• Check TargetID: Checks current TargetID from EID0 and EID5
• Toggle Host Information on XMB: Enables/disables host information on XMB
• Toggle XMB Mode: Switch between CEX and DEX XMB
• Toggle Debug Settings: Switch between CEX and DEX Debug settings
• Show Information: Shows current Firmware, Kernel, TargetID, VSH, XMB Host and Debug Settings

Service Tools
• Display Applicable Version: Displays minimum downgrade version
• Check File System: Reboots and allows you to check and repair filesystem
• Rebuild Database: Reboots with Database rebuilding flag set
• Toggle Recovery Mode: Reboot to Recovery Mode (Not supported on NAND models!)

Service Tools > Advanced Service Tools
• RSOD fix: Re-initialize VTRM-Region to attempt to fix RSOD
• Toggle Factory Service Mode: Enter/Exit Factory Service Mode (DON’T INSTALL CFW ON FSM)
• Remarry Bluray Drive: Requires: Enter to FSM and copy "eid_root_key" to /dev_usb
• Toggle HDD Space: Unlocks/restores 8% extra total space on the PS3 internal HDD
• Show ROS Bank: Shows active ROS bank
• Check 8th SPE: Checks if 8th SPE is currently enabled or disabled
• Toggle 8th SPE: Enables/disables 8th SPE
• Enable VSH Debugging: Enables debugging vsh.self
• Enable Support for DEX OFW: Enables OFW DEX installation on converted PS3 Retail
• Disable Support for DEX OFW: Disables OFW DEX installation on converted PS3 Retail
• Load LV2 kernel: Loads lv2_kernel.self file from /dev_usb000 or /dev_flash

Updates
• xai_plugin: Downloads the latest update of xai plugin
• PS2 EMUs Cobra: Downloads the latest update of PS1/PS2 EMUs Cobra
• PS2 EMUs MOD: Downloads the latest update of PS1/PS2 EMUs MOD by mrjaredbeta and kozarovv
```
