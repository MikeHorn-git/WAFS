#Requires -RunAsAdministrator

#################################################################################
#MIT License                                                                    #
#                                                                               #
#Copyright (c) 2023 MikeHorn-git                                                #
#                                                                               #
#Permission is hereby granted, free of charge, to any person obtaining a copy	#
#of this software and associated documentation files (the "Software"), to deal	#
#in the Software without restriction, including without limitation the rights	#
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      #
#copies of the Software, and to permit persons to whom the Software is          #
#furnished to do so, subject to the following conditions:                       #
#                                                                               #
#The above copyright notice and this permission notice shall be included in all	#
#copies or substantial portions of the Software.                                #
#                                                                               #
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     #
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       #
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE	#
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         #
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,	#
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE	#
#SOFTWARE.                                                                      #
#################################################################################

param (
    [switch]$all,
    [switch]$anti,
    [switch]$tools
)

function anti {

    Write-Host '[+] Anti-Forensics Script' -foregroundcolor "DarkGray"

    # Disable Audit Success logs
    auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:enable 2>$null

    # Clean Chrome cache
    Remove-Item -Path "$Home\AppData\Local\Google\Chrome\User Data\Default\Cache" -Recurse -Force 2>$null

    # Clean Chrome history
    Remove-Item -Path "$Home\AppData\Local\Google\Chrome\User Data\Default\History" -Recurse -Force 2>$null

    # Clean Chrome Session Restore
    Remove-Item -Path "$Home\AppData\Local\Google\Chrome\User Data\Default" -Recurse -Force 2>$null

    # Remove Cortana
    Get-AppxPackage -AllUsers Microsoft.549981C3F5F10 | Remove-AppPackage 2>$null

    # Clean DNS cache
    ipconfig /flushdns >$null

    # Clean Edge cache
    Remove-Item -Path "$Home\AppData\Local\Packages\microsoft.microsoftedge_*\AC\MicrosoftEdge\Cache" -Recurse -Force 2>$null

    # Clean Edge / Internet Explorer history
    Remove-Item -Path 'HKCU:\Software\Microsoft\Internet Explorer\TypedURLs' -Recurse -Force 2>$null
    Remove-Item -Path "$Home\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat" -Force 2>$null

    # Clean Firefox cache
    Remove-Item -Path "$Home\AppData\Local\Mozilla\Firefox\Profiles\*.default\Cache" -Recurse -Force 2>$null

    # Clean Firefox history
    Remove-Item -Path "$Home\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\places.sqlite" -Force 2>$null

    # Clean Firefox Session Restore
    Remove-Item -Path "$Home\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\sessionstore.js" -Force 2>$null

    # Clean Internet Explorer cache
    Remove-Item -Path "$Home\AppData\Local\Microsoft\Windows\INetCache\IE" -Recurse -Force 2>$null
    Remove-Item -Path "$Home\AppData\Local\Microsoft\Internet Explorer\CacheStorage" -Recurse -Force 2>$null

    # Clean Internet Explorer Session Restore
    Remove-Item -Path "$Home\AppData\Local\Microsoft\Internet Explorer\Recovery" -Recurse -Force 2>$null

    # Disable Keylogger
    Stop-Service -Name DiagTrack -Force 2>$null
    Set-Service -Name DiagTrack -StartupType Disabled 2>$null
    Stop-Service -Name dmwappushservice -Force 2>$null
    Set-Service -Name dmwappushservice -StartupType Disabled 2>$null

    Write-Output "" > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl 2>$null

    # Clean Last-Visited MRU
    Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU' -Recurse -Force 2>$null

    # Disable NTFS Last Access Time
    Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' | New-ItemProperty -Name 'NtfsDisableLastAccessUpdate' -Value "1" -PropertyType DWORD -Force >$null
    fsutil behavior set disablelastaccess 3 >$null

    # Clean OpenSaveMRU
    Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU' -Recurse -Force 2>$null

    # Clean Plug and Play Logs
    Remove-Item -Path "C:\Windows\INF\setupapi.dev*\" -Force 2>$null
    
    # Disable Prefetch
    Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' | New-ItemProperty -Name 'EnablePrefetcher' -Value "0" -PropertyType DWORD -Force >$null
    Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' | New-ItemProperty -Name 'EnableSuperfetch' -Value "0" -PropertyType DWORD -Force >$null

    # Clean Prefetch
    Remove-Item -Path "C:\Windows\Prefetch" -Recurse -Force 2>$null
    
    # Clean Recent Items
    Remove-Item -Path "$HOME\AppData\Roaming\Microsoft\Windows\Recent" -Recurse 2>$null
    Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs' -Recurse -Force 2>$null
    
    # Clean RecycleBin
    Clear-RecycleBin -Force 2>$null

    # Clean Run Command history
    Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -Recurse -Force 2>$null
    
    # Disable Shadow Copies
    Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToBackup' -Recurse -Force 2>$null

    # Disable previous Shadow Copies
    Get-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\' | New-ItemProperty -Name 'DisableLocalPage' -Value "1" -PropertyType DWORD -Force >$null

    # Clean Shadow Copies
    vssadmin delete shadows /All >$null

    # Disable ShellBags
    Get-Item -Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell' | New-ItemProperty -Name 'BagMRU Size' -Value "1" -PropertyType DWORD -Force >$null 

    # Clean ShellBags
    Remove-Item -Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell' -Recurse -Force 2>$null
    Remove-Item -Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\ShellNoRoam' -Recurse -Force 2>$null
    Remove-Item -Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\' -Recurse -Force 2>$null
    Remove-Item -Path 'HKCU:\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\' -Recurse -Force 2>$null

    # Clean Simcache
    Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\' -Recurse -Force 2>$null
 
    # Clean System Resource Usage Monitor database
    Remove-Item -Path "C:\Windows\System32\sru\SRUDB.dat" -Force 2>$null

    # Clean Temp files
    Remove-Item -Path "C:\Windows\temp\*" -Recurse -Force 2>$null
    
    # Clean Thumbcache
    Remove-Item -Path "$Home\AppData\Local\Microsoft\Windows\Explorer\thumbcache*.db\" -Recurse -Force 2>$null

    # Clean USB history
    Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -Recurse -Force 2>$null
    Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' -Recurse -Force 2>$null
    
    # Disable UserAssist
    Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' | New-ItemProperty -Name 'Start_TrackProgs' -Value "0" -PropertyType DWORD -Force >$null
    Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' | New-ItemProperty -Name 'Start_TrackEnabled' -Value "0" -PropertyType DWORD -Force >$null

    # Clean UserAssist
    Remove-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\' -Recurse -Force 2>$null

    # Clean VPN cache
    Remove-Item -Path 'HKLM:\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache' -Recurse -Force 2>$null

    # Disable Windows Event logs
    Stop-Service -Name EventLog -Force 2>$null
    Set-Service EventLog -StartupType Disabled

    # Clean Windows Event logs
    wevtutil el | Foreach-Object {wevtutil cl "$_"} 2>$null
    
    # Clean Windows logs
    Get-EventLog -LogName * | ForEach-Object { Clear-EventLog $_.Log } 2>$null

    # Disable Windows Timeline DB
    Stop-Service -Name CDPUserSvc* -Force 2>$null
    
    # Clean Windows Timeline DB
    Remove-Item -Path "$Home\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db" -Force
  
    # Disable $UsnJrnl
    fsutil usn deletejournal /d c: 2>$null

    # Clean Powershell history
    Remove-Item -Path "$HOME\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Force 2>$null
    Clear-History 2>$null

    Write-Host '[+] Done, reboot your system' -foregroundcolor "DarkGray"
    Exit 0
}


function tools {

    Write-Host '[+] Tools Script' -foregroundcolor "DarkGray"

    # Create Tools folder
    New-Item -Path "$HOME" -Name "Tools" -ItemType Directory >$null

    # Download Bleachbit
    $URL = "https://www.bleachbit.org/download/file/t?file=BleachBit-4.4.2-portable.zip"
    $Path = "$Home\Tools\BleachBit-4.4.2-portable.zip"
    Invoke-WebRequest -URI $URL -OutFile $Path
    Expand-Archive $Path -DestinationPath "$HOME\Tools\" 2>$null
    Remove-Item $Path 2>$null

    # Download BusKill
    $URL = "https://github.com/BusKill/buskill-app/releases/download/v0.7.0/buskill-win-v0.7.0-x86_64.zip"
    $Path = "$Home\Tools\buskill.zip"
    Invoke-WebRequest -URI $URL -OutFile $Path
    Expand-Archive $Path -DestinationPath "$HOME\Tools\" 2>$null
    Remove-Item $Path
    
    # Download ClamAV
    $URL = "https://www.clamav.net/downloads/production/clamav-1.1.1.win.x64.zip"
    $Path = "$Home\Downloads\clamav-1.1.1.win.x64.zip"
    Invoke-WebRequest -URI $URL -OutFile $Path
    Expand-Archive $Path -DestinationPath "$HOME\Tools\" 2>$null
    Remove-Item $Path 2>$null

    # Download delete-self-poc
    $URL = "https://github.com/LloydLabs/delete-self-poc/releases/download/v1.1/ds_x64.exe"
    $Path = "$Home\Tools\ds_x64.exe"
    Invoke-WebRequest -URI $URL -OutFile $Path 2>$null

    # Download Exifpilot
    $URL = "https://www.two-pilots.com/colorpilot.com/load/exif_64.exe"
    $Path = "$Home\Tools\exif_64.exe"
    Invoke-WebRequest -URI $URL -OutFile $Path 2>$null

    # Download KeePassXC
    $URL = "https://github.com/keepassxreboot/keepassxc/releases/download/2.7.6/KeePassXC-2.7.6-Win64.zip"
    $Path = "$Home\Tools\KeePassXC.zip"
    Invoke-WebRequest -URI $URL -OutFile $Path 2>$null
    Expand-Archive $Path -DestinationPath "$HOME\Tools\" 2>$null
    Remove-Item $Path 2>$null

    # Download SDelete (sysinternal suite)
    $URL = "https://download.sysinternals.com/files/SDelete.zip"
    $Path = "$Home\Tools\SDelete.zip"
    Invoke-WebRequest -URI $URL -OutFile $Path
    Expand-Archive $Path -DestinationPath "$HOME\Tools\SDelete" 2>$null
    Remove-Item $Path 2>$null

    # Download Timestomper
    $URL = "https://github.com/slyd0g/TimeStomper/blob/master/Release/TimeStomper.exe"
    $Path = "$Home\Tools\TimeStomper.exe"
    Invoke-WebRequest -URI $URL -OutFile $Path 2>$null

    # Download USB Sentinel
    $URL = "https://github.com/thereisnotime/xxUSBSentinel/releases/download/v1/xxUSBSentinel.exe"
    $Path = "$Home\Tools\xxUSBSentinel.exe"
    Invoke-WebRequest -URI $URL -OutFile $Path 2>$null

    # Download VeraCrypt
    $URL = "https://launchpad.net/veracrypt/trunk/1.25.9/+download/VeraCrypt%20Portable%201.25.9.exe"
    $Path = "$Home\Tools\VeraCrypt.exe"
    Invoke-WebRequest -URI $URL -OutFile $Path
}

function usage {
    Write-Host "
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
    "
}

function main {
    if ($all) {
        Start-Transcript -Path ".\logs_all.txt"
        tools
        anti
        Stop-Transcript
    }
    elseif ($anti){
        Start-Transcript -Path ".\logs_anti.txt"
        anti
        Stop-Transcript
    }
    elseif ($tools){
        Start-Transcript -Path ".\logs_tools.txt"
        tools
        Write-Host '[+] Done, reboot your system' -foregroundcolor "DarkGray"
        Exit 0
        Stop-Transcript
    }
    else {
        usage
    }
}
main:qa
