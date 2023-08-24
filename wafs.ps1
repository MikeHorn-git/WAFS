#Requires -RunAsAdministrator

#################################################################################
#MIT License									#
#										#
#Copyright (c) 2023 MikeHorn-git						#
#										#
#Permission is hereby granted, free of charge, to any person obtaining a copy	#
#of this software and associated documentation files (the "Software"), to deal	#
#in the Software without restriction, including without limitation the rights	#
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell	#
#copies of the Software, and to permit persons to whom the Software is		#
#furnished to do so, subject to the following conditions:			#
#										#
#The above copyright notice and this permission notice shall be included in all	#
#copies or substantial portions of the Software.				#
#									        #
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR	#
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,	#
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE	#
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER		#
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,	#
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE	#
#SOFTWARE.									#
#################################################################################

param (
    [switch]$all,
    [switch]$anti,
    [switch]$tools
)

function anti {

    Write-Host '[+] Anti-Forensics Script'
    # Disable Timestamps - UserAssist
    Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' | New-ItemProperty -Name 'Start_TrackProgs' -Value "0" -PropertyType DWORD -Force 2>$null
    Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' | New-ItemProperty -Name 'Start_TrackEnabled' -Value "0" -PropertyType DWORD -Force 2>$null

    # Clear Timestamps - UserAssist
    Remove-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\' -Recurse 2>$null

    # Disable Timestamps - Prefetch
    Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' | New-ItemProperty -Name 'EnablePrefetcher' -Value "0" -PropertyType DWORD -Force 2>$null
    Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' | New-ItemProperty -Name 'EnableSuperfetch' -Value "0" -PropertyType DWORD -Force 2>$null

    # Disable Timestamps - Last Access Time
    Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' | New-ItemProperty -Name 'NtfsDisableLastAccessUpdate' -Value "1" -PropertyType DWORD -Force 2>$null
    
    # Disable Shadow Copies
    Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToBackup' -Recurse 2>$null

    # Disable previous Shadow Copies
    Get-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\' | New-ItemProperty -Name 'DisableLocalPage' -Value "1" -PropertyType DWORD -Force 2>$null

    # Delete Shadow Copies
    vssadmin delete shadows /All 2>$null

    # Disable ShellBags
    Get-Item -Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell' | New-ItemProperty -Name 'BagMRU Size' -Value "1" -PropertyType DWORD -Force 2>$null 

    # Delete ShellBags
    Remove-Item -Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell' -Recurse 2>$null
    Remove-Item -Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\ShellNoRoam' -Recurse 2>$null
    Remove-Item -Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\' -Recurse 2>$null
    Remove-Item -Path 'HKCU:\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\' -Recurse 2>$null

    # Disable Windows event logs
    #Disable the Event Log service
    sc config eventlog start= disabled 2>$null
    net start eventlog 2>$null
    #Disable registering Audit Success logs
    auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:enable 2>$null

    # Disable $UsnJrnl
    fsutil usn deletejournal /d c: 2>$null

    # Disable Keylogger
    Write-Host "[+] Disable Keylogger"
    sc delete DiagTrack 2>$null
    sc delete dmwappushservice 2>$null
    Write-Output "" > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl 2>$null

    # Disable NTFS Last Access TimeStamp
    fsutil behavior set disablelastaccess 3 2>$null
    # Delete Windows event logs
    Get-EventLog -LogName * | ForEach-Object { Clear-EventLog $_.Log } 2>$null

    # Delete Recent Items
    Remove-Item -Path '$HOME\AppData\Roaming\Microsoft\Windows\Recent' -Recurse 2>$null
    Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs' -Recurse 2>$null

    # Delete Simcache
    Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\' -Recurse 2>$null
 
    # Delete System Resource Usage Monitor database
    Remove-Item -Path 'C:\Windows\System32\sru\SRUDB.dat' -Recurse 2>$null

    # Delete Last-Visited MRU
    Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU' -Recurse 2>$null

    # Delete OpenSaveMRU
    Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU' -Recurse 2>$null
   
    # Delete Windows Timeline DB
    #Remove-Item -Path 'C:\Users\flare\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db' -Recurse

    # Delete Winevt logs
    #Remove-Item -Path 'C:\Windows\System32\winevt\Logs' -Recurse

    # Delete Thumbcache
    Remove-Item -Path "$Home\AppData\Local\Microsoft\Windows\Explorer\thumbcache*.db\" 2>$null

    # Clear Temp files
    Remove-Item -Path 'C:\Windows\temp\*' -Recurse 2>$null

    Clear-RecycleBin -Force 2>$null

    # Delete VPN cache
    Remove-Item -Path 'HKLM:\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache' -Recurse 2>$null

    # Delete Chrome cache
    Remove-Item -Path '$Home\AppData\Local\Google\Chrome\User Data\Default\Cache' -Force 2>$null

    # Delete Firefox cache
    Remove-Item -Path '$Home\AppData\Local\Mozilla\Firefox\Profiles\*.default\Cache' -Force 2>$null
   
    # Delete Chrome history
    Remove-Item -Path '$Home\AppData\Local\Google\Chrome\User Data\Default\History' -Force 2>$null

    # Delete Firefox history
    Remove-Item -Path '$Home\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\places.sqlite' -Force 2>$null
    
    # Delete Internet Explorer history
    Remove-Item -Path 'HKCU:\Software\Microsoft\Internet Explorer\TypedURLs' -Recurse 2>$null

    # Delete USB history
    Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -Recurse 2>$null
    Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' -Recurse 2>$null

    # Delete Run Command history
    Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -Recurse 2>$null

    # Flush DNS cache
    ipconfig /flushdns 2>$null
    
    # Remove Cortana
    Get-AppxPackage -AllUsers Microsoft.549981C3F5F10 | Remove-AppPackage 2>$null

    # Delete Powershell history
    Remove-Item -Path "$HOME\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>$null
    Clear-History 2>$null
}


function tools {

    Write-Host '[+] Tools Script'
    # Create Tools folder
    New-Item -Path "$HOME" -Name "Tools" -ItemType Directory 2>$null

    # Download bleachbit
    $URL = "https://www.bleachbit.org/download/file/t?file=BleachBit-4.4.2-portable.zip"
    $Path = "$Home\Tools\bleachbit.zip"
    Invoke-WebRequest -URI $URL -OutFile $Path
    Expand-Archive $Path -DestinationPath "$HOME\Tools\bleachbit" 2>$null
    Remove-Item $Path 2>$null

    # Download BusKill
    $URL = "https://github.com/BusKill/buskill-app/releases/download/v0.7.0/buskill-win-v0.7.0-x86_64.zip"
    $Path = "$Home\Tools\buskill.zip"
    Invoke-WebRequest -URI $URL -OutFile $Path
    Expand-Archive $Path -DestinationPath "$HOME\Tools\buskill" 2>$null
    Remove-Item $Path
    
    # Download clamav
    $URL = "https://www.clamav.net/downloads/production/clamav-1.1.1.win.x64.msi"
    $Path = "$Home\Downloads\clamav.msi"
    Invoke-WebRequest -URI $URL -OutFile $Path
    Start-Process msiexec.exe -Wait -ArgumentList '/I $Path /quiet' 2>$null
    Remove-Item $Path 2>$null

    # Download delete-self-poc
    $URL = "https://github.com/LloydLabs/delete-self-poc/releases/download/v1.1/ds_x64.exe"
    $Path = "$Home\Tools\ds_x64.exe"
    Invoke-WebRequest -URI $URL -OutFile $Path 2>$null

    # Download exifpilot
    $URL = "https://www.two-pilots.com/colorpilot.com/load/exif_64.exe"
    $Path = "$Home\Tools\exif_64.exe"
    Invoke-WebRequest -URI $URL -OutFile $Path 2>$null

    # Download FreeOTF
    $URL = "https://sourceforge.net/projects/freeotfe.mirror/files/latest/download"
    $Path = "$Home\Tools\FreeOTFE_5_21.exe"
    Invoke-WebRequest -URI $URL -OutFile $Path
    Start-Process -FilePath "$Path" -ArgumentList '/S /v /qn' -Wait 2>$null

    # Download SDelete (sysinternal suite)
    $URL = "https://download.sysinternals.com/files/SDelete.zip"
    $Path = "$Home\Tools\SDelete.zip"
    Invoke-WebRequest -URI $URL -OutFile $Path
    Expand-Archive $Path -DestinationPath "$HOME\Tools\SDelete" 2>$null
    Remove-Item $Path 2>$null

    # Download timestomper
    $URL = "https://github.com/slyd0g/TimeStomper/blob/master/Release/TimeStomper.exe"
    $Path = "$Home\Tools\TimeStomper.exe"
    Invoke-WebRequest -URI $URL -OutFile $Path 2>$null

    # Download USB Sentinel
    $URL = "https://github.com/thereisnotime/xxUSBSentinel/releases/download/v1/xxUSBSentinel.exe"
    $Path = "$Home\Tools\xxUSBSentinel.exe"
    Invoke-WebRequest -URI $URL -OutFile $Path 2>$null
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
        anti
        tools
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
        Stop-Transcript
    }
    else {
        usage
    }
}
main