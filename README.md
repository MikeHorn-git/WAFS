# Windows Anti-Forensics Script

![BlackWindows](https://github.com/MikeHorn-git/WAFS/assets/123373126/1667f6e9-273a-4f02-b242-d95659ed76e0)

# ⚠️ Warning
Backup your data and your registry before.

# Description
Windows Anti-Forensics Script (WAFS) aim to make forensics investigations on a Windows OS more difficult. WAFS allow you to clean/disable certain files, services, registry keys. And WAFS provide some anti-forensics tools to improve countering forensics analysis.

# Installation
```bash
git clone https://github.com/MikeHorn-git/WAFS.git
cd WAFS
#Run Powershell with administrator privilege
.\WAFS.ps1
```

# 🪶 Usage
```bash
██╗    ██╗ █████╗ ███████╗███████╗
██║    ██║██╔══██╗██╔════╝██╔════╝
██║ █╗ ██║███████║█████╗  ███████╗
██║███╗██║██╔══██║██╔══╝  ╚════██║
╚███╔███╔╝██║  ██║██║     ███████║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚══════╝
                                  
Windows Anti-Forensics Script

Syntax: wafs.ps1 -[all|anti|tools]
options:
-all                Install both features.
-anti               Disable and clear certains windows features and parameters for anti-forensics.
-tools              Install anti-forensics tools.
```

# 🛠️ Features
* Clean
   * Chrome cache - history - session restore
   * DNS cache
   * Edge cache - history
   * Firefox cache - history
   * Internet Explorer cache - history - session restore
   * Last-Visited MRU
   * OpenSave MRU
   * Plug and Play logs
   * PowerShell history
   * Prefetch
   * Recent items
   * RecycleBin
   * Run command history
   * Shadow copies
   * Shellbags
   * Simcache
   * System Resource Usage Monitor
   * Tempory files
   * Thumbcache
   * USB history
   * User Assist
   * VPN cache
   * Windows Timeline
  
* Disable
  * Keylogger
  * NTFS Last Acces Time
  * Prefetch
  * Shadow Copies
  * Shellbags
  * User Assist
  * UsnJrnl
  * Windows Event Logs
  * Windows Timeline

* Remove
  * Cortana

# Tools
* [Bleachbit](https://www.bleachbit.org/)
* [BusKill](https://github.com/BusKill/buskill-app)
* [ClamAV](https://www.clamav.net/)
* [Delete-self-poc](https://github.com/LloydLabs/delete-self-poc)
* [ExivPilot](https://www.colorpilot.com/)
* [KeePassXC](https://keepassxc.org/)
* [SDelete](https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete)
* [TimeStomper](https://github.com/slyd0g/TimeStomper)
* [USBSentinel](https://github.com/thereisnotime/xxUSBSentinel/)
* [VeraCrypt](https://www.veracrypt.fr/en/Home.html)

# Credits
* [Awesome anti-forensic](https://github.com/shadawck/awesome-anti-forensic)
* [Background](https://wallpapercave.com/wp/wp3438728.jpg)
* [Sans Forensics](https://www.sans.org/posters/windows-forensic-analysis/)
