# 🔐 Windows Anti-Forensics Script

![black-windows-10-logo](https://github.com/MikeHorn-git/WAFS/assets/123373126/32917e73-50f1-41f5-931b-1ad7304f4db1)

# ⚠️ Warning
Make a backup of your files and your registry before execute this script. WAFS delete and modify registry keys values and windows services.

# 👷 Installation
```bash
git clone https://github.com/MikeHorn-git/WAFS.git
cd WAFS
#Run Powershell with administrator privilege
.\wafs.ps1
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
   * Chrome cache
   * Chrome history
   * DNS cache
   * Firefox cache
   * Firefox history
   * Last-Visited MRU
   * OpenSave MRU
   * PowerShell history
   * Recent items
   * Recycle bin
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

* Remove
  * Cortana

# 🛠️ Tools
* [Bleachbit](https://www.bleachbit.org/)
* [BusKill](https://github.com/BusKill/buskill-app)
* [ClamAV](https://www.clamav.net/)
* [Delete-self-poc](https://github.com/LloydLabs/delete-self-poc)
* [ExivPilot](https://www.colorpilot.com/)
* [FreeOTFE](https://en.wikipedia.org/wiki/FreeOTFE)
* [SDelete](https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete)
* [TimeStomper](https://github.com/slyd0g/TimeStomper)
* [USBSentinel](https://github.com/thereisnotime/xxUSBSentinel/)

# ✉️ Credits
* [Awesome anti-forensic](https://github.com/shadawck/awesome-anti-forensic)
* [Hacktricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/anti-forensic-techniques#disable-shadow-copies).
* [Sans Forensics](https://www.sans.org/posters/windows-forensic-analysis/).

# 📡 To-Do
- [ ] Add an option to shred files rather than delete them.
- [ ] Improve the script skills
