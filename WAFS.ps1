#Requires -RunAsAdministrator

#################################################################################
#MIT License                                                                    #
#                                                                               #
#Copyright (c) 2023-2024 MikeHorn-git                                           #
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

<#
    .SYNOPSIS
    Windows Anti-Forensics Script (WAFS) hardened your Windows OS against forensics analysis.

    .DESCRIPTION
    Windows Anti-Forensics Script (WAFS) aim to make forensics investigations on a Windows OS more difficult.
    WAFS allow you to clean/disable certain files, services, registry keys.
    And WAFS provide some anti-forensics tools to improve countering forensics analysis.

    To execute this script:
      1) Open PowerShell window as administrator
      2) Execute the script by running ".\WAFS.ps1"

    .PARAMETER all
    Current user password to allow reboot resiliency via Boxstarter. The script prompts for the password if not provided.

    .PARAMETER anti
    Switch parameter indicating a password is not needed for reboots.

    .EXAMPLE
    .\WAFS.ps1 -anti

    Description
    ---------------------------------------
    Disable and clear certains windows features and parameters for anti-forensics.

    .LINK
    https://github.com/MikeHorn-git/WAFS
#>

[CmdletBinding()]
param (
    [switch]$all,
    [switch]$anti,
    [switch]$tools,
    [switch]$clean,
    [switch]$disable
)

function Invoke-AntiForensics {
    Write-Output '[+] Anti-Forensics Script'

    # Cleaning
    $PathsToRemove = @{
        'ChromeCache'           = "$Home\AppData\Local\Google\Chrome\User Data\Default\Cache"
        'ChromeHistory'         = "$Home\AppData\Local\Google\Chrome\User Data\Default\History"
        'ChromeSessionRestore'  = "$Home\AppData\Local\Google\Chrome\User Data\Default"
        'EdgeCache'             = "$Home\AppData\Local\Packages\microsoft.microsoftedge_*\AC\MicrosoftEdge\Cache"
        'IEHistory'             = 'HKCU:\Software\Microsoft\Internet Explorer\TypedURLs'
        'IEWebCache'            = "$Home\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat"
        'FirefoxCache'          = "$Home\AppData\Local\Mozilla\Firefox\Profiles\*.default\Cache"
        'FirefoxHistory'        = "$Home\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\places.sqlite"
        'FirefoxSessionRestore' = "$Home\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\sessionstore.js"
        'IECache'               = "$Home\AppData\Local\Microsoft\Windows\INetCache\IE"
        'IECacheStorage'        = "$Home\AppData\Local\Microsoft\Internet Explorer\CacheStorage"
        'IESessionRestore'      = "$Home\AppData\Local\Microsoft\Internet Explorer\Recovery"
        'LastVisitedMRU'        = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU'
        'OpenSaveMRU'           = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU'
        'PlugAndPlayLogs'       = "C:\Windows\INF\setupapi.dev*"
        'Prefetch'              = "C:\Windows\Prefetch"
        'RecentItems'           = "$HOME\AppData\Roaming\Microsoft\Windows\Recent"
        'RecentDocs'            = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'
        'RunMRU'                = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
        'ShadowCopies'          = 'HKLM:\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToBackup'
        'ShellBags'             = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell'
        'ShellNoRoam'           = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\ShellNoRoam'
        'ShellWow6432'          = 'HKCU:\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\'
        'Simcache'              = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\'
        'SRUDB'                 = "C:\Windows\System32\sru\SRUDB.dat"
        'TempFiles'             = "C:\Windows\temp\*"
        'Thumbcache'            = "$Home\AppData\Local\Microsoft\Windows\Explorer\thumbcache*.db\"
        'USBHistory'            = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
        'USBEnum'               = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB'
        'UserAssist'            = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\'
        'VPNCache'              = 'HKLM:\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache'
        'TimelineDB'            = "$Home\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db"
        'PowerShellHistory'     = "$HOME\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    }

    foreach ($pathKey in $PathsToRemove.Keys) {
        $path = $PathsToRemove[$pathKey]
        if ($null -ne $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-Output "Removed: $path"
            }
            catch {
                Write-Error "Failed to remove: $path. Error: $_"
            }
        }
    }

    # Disable 
    try {
        # Disable Audit Success logs
        auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:enable 2>$null

        # Remove Cortana
        Get-AppxPackage -AllUsers Microsoft.549981C3F5F10 | Remove-AppPackage 2>$null

        # Clean DNS cache
        ipconfig /flushdns >$null

        # Disable Keylogger
        Stop-Service -Name DiagTrack -Force 2>$null
        Set-Service -Name DiagTrack -StartupType Disabled 2>$null
        Stop-Service -Name dmwappushservice -Force 2>$null
        Set-Service -Name dmwappushservice -StartupType Disabled 2>$null
        Write-Output "" > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl 2>$null

        # Disable NTFS Last Access Time
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'NtfsDisableLastAccessUpdate' -Value 1 -Force
        fsutil behavior set disablelastaccess 3 >$null

        # Disable Prefetch
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' -Name 'EnablePrefetcher' -Value 0 -Force
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' -Name 'EnableSuperfetch' -Value 0 -Force

        # Clean RecycleBin
        Clear-RecycleBin -Force 2>$null

        # Disable previous Shadow Copies
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\' -Name 'DisableLocalPage' -Value 1 -Force

        # Clean Shadow Copies
        vssadmin delete shadows /All >$null

        # Disable ShellBags
        Set-ItemProperty -Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell' -Name 'BagMRU Size' -Value 1 -Force

        # Disable UserAssist
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' -Name 'Start_TrackProgs' -Value 0 -Force
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' -Name 'Start_TrackEnabled' -Value 0 -Force

        # Disable Windows Event logs
        Stop-Service -Name EventLog -Force 2>$null
        Set-Service EventLog -StartupType Disabled

        # Clean Windows Event logs
        wevtutil el | ForEach-Object { wevtutil cl "$_" } 2>$null

        # Clean Windows logs
        Get-EventLog -LogName * | ForEach-Object { Clear-EventLog $_.Log } 2>$null

        # Disable Windows Timeline DB
        Stop-Service -Name CDPUserSvc* -Force 2>$null

        # Disable $UsnJrnl
        fsutil usn deletejournal /d c: 2>$null

        # Clean Powershell history
        Clear-History 2>$null
    }
    catch {
        Write-Error "An error occurred: $_"
    }

    Write-Output '[+] Done, reboot your system'
    Exit 0
}

function Invoke-Cleaning {
    
    Write-Output '[+] Anti-Forensics Script - Cleaning'
    
    $PathsToRemove = @{
        'ChromeCache'                   = "$Home\AppData\Local\Google\Chrome\User Data\Default\Cache"
        'ChromeHistory'                 = "$Home\AppData\Local\Google\Chrome\User Data\Default\History"
        'ChromeSessionRestore'          = "$Home\AppData\Local\Google\Chrome\User Data\Default"
        'EdgeCache'                     = "$Home\AppData\Local\Packages\microsoft.microsoftedge_*\AC\MicrosoftEdge\Cache"
        'IEHistory'                     = 'HKCU:\Software\Microsoft\Internet Explorer\TypedURLs'
        'IEWebCache'                    = "$Home\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat"
        'FirefoxCache'                  = "$Home\AppData\Local\Mozilla\Firefox\Profiles\*.default\Cache"
        'FirefoxHistory'                = "$Home\AppData\Roaming\Mozilla\Firefox\Profiles\*.default*\places.sqlite"
        'FirefoxHistoryBackup'          = "$Home\AppData\Roaming\Mozilla\Firefox\Profiles\*.default*\places.sqlite-*"
        'FirefoxBookmarks'              = "$Home\AppData\Roaming\Mozilla\Firefox\Profiles\*.default*\bookmarkbackups\*"
        'FirefoxSessionRestore'         = "$Home\AppData\Roaming\Mozilla\Firefox\Profiles\*.default*\sessionstore.js"
        'FirefoxSessionRestoreBackup'   = "$Home\AppData\Roaming\Mozilla\Firefox\Profiles\*.default*\sessionstore-backups\*"
        'FirefoxCookies'                = "$Home\AppData\Roaming\Mozilla\Firefox\Profiles\*.default*\cookies.sqlite*"
        'IECache'                       = "$Home\AppData\Local\Microsoft\Windows\INetCache\IE"
        'IECacheStorage'                = "$Home\AppData\Local\Microsoft\Internet Explorer\CacheStorage"
        'IESessionRestore'              = "$Home\AppData\Local\Microsoft\Internet Explorer\Recovery"
        'LastVisitedMRU'                = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU'
        'OpenSaveMRU'                   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU'
        'PlugAndPlayLogs'               = "C:\Windows\INF\setupapi.dev*"
        'Prefetch'                      = "C:\Windows\Prefetch"
        'RecentItems'                   = "$HOME\AppData\Roaming\Microsoft\Windows\Recent"
        'RecentDocs'                    = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'
        'RunMRU'                        = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
        'ShadowCopies'                  = 'HKLM:\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToBackup'
        'ShellBags'                     = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell'
        'ShellNoRoam'                   = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\ShellNoRoam'
        'ShellWow6432'                  = 'HKCU:\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\'
        'Simcache'                      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\'
        'SRUDB'                         = "C:\Windows\System32\sru\SRUDB.dat"
        'TempFiles'                     = "C:\Windows\temp\*"
        'Thumbcache'                    = "$Home\AppData\Local\Microsoft\Windows\Explorer\thumbcache*.db\"
        'USBHistory'                    = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
        'USBEnum'                       = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB'
        'UserAssist'                    = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\'
        'VPNCache'                      = 'HKLM:\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache'
        'TimelineDB'                    = "$Home\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db"
        'PowerShellHistory'             = "$HOME\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    }

    foreach ($pathKey in $PathsToRemove.Keys) {
        $path = $PathsToRemove[$pathKey]
        if ($null -ne $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-Output "Removed: $path"
            }
            catch {
                Write-Error "Failed to remove: $path. Error: $_"
            }
        }
    }
}

function Invoke-Disable {
    Write-Output '[+] Anti-Forensics Script - Disable'
    try {
        # Disable Audit Success logs
        auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:enable 2>$null

        # Remove Cortana
        Get-AppxPackage -AllUsers Microsoft.549981C3F5F10 | Remove-AppPackage 2>$null

        # Clean DNS cache
        ipconfig /flushdns >$null

        # Disable Keylogger
        Stop-Service -Name DiagTrack -Force 2>$null
        Set-Service -Name DiagTrack -StartupType Disabled 2>$null
        Stop-Service -Name dmwappushservice -Force 2>$null
        Set-Service -Name dmwappushservice -StartupType Disabled 2>$null
        Write-Output "" > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl 2>$null

        # Disable NTFS Last Access Time
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'NtfsDisableLastAccessUpdate' -Value 1 -Force
        fsutil behavior set disablelastaccess 3 >$null

        # Disable Prefetch
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' -Name 'EnablePrefetcher' -Value 0 -Force
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' -Name 'EnableSuperfetch' -Value 0 -Force

        # Clean RecycleBin
        Clear-RecycleBin -Force 2>$null

        # Disable previous Shadow Copies
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\' -Name 'DisableLocalPage' -Value 1 -Force

        # Clean Shadow Copies
        vssadmin delete shadows /All >$null

        # Disable ShellBags
        Set-ItemProperty -Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell' -Name 'BagMRU Size' -Value 1 -Force

        # Disable UserAssist
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' -Name 'Start_TrackProgs' -Value 0 -Force
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' -Name 'Start_TrackEnabled' -Value 0 -Force

        # Disable Windows Event logs
        Stop-Service -Name EventLog -Force 2>$null
        Set-Service EventLog -StartupType Disabled

        # Clean Windows Event logs
        wevtutil el | ForEach-Object { wevtutil cl "$_" } 2>$null

        # Clean Windows logs
        Get-EventLog -LogName * | ForEach-Object { Clear-EventLog $_.Log } 2>$null

        # Disable Windows Timeline DB
        Stop-Service -Name CDPUserSvc* -Force 2>$null

        # Disable $UsnJrnl
        fsutil usn deletejournal /d c: 2>$null

        # Clean Powershell history
        Clear-History 2>$null
    }
    catch {
        Write-Error "An error occurred: $_"
    }

    Write-Output '[+] Done, reboot your system'
    Exit 0

}

function Install-Tools {
    Write-Output '[+] Tools Script'
    $toolsDirectory = "$HOME\Tools"
    New-Item -Path $toolsDirectory -ItemType Directory -Force >$null

    # URLs of tools to download
    $FastURL = [ordered]@{
        DSP         = "https://github.com/LloydLabs/delete-self-poc/releases/download/v1.1/ds_x64.exe"
        Exif        = "https://www.two-pilots.com/colorpilot.com/load/exif_64.exe"
        Timestomper = "https://github.com/slyd0g/TimeStomper/blob/master/Release/TimeStomper.exe"
        USBSentinel = "https://github.com/thereisnotime/xxUSBSentinel/releases/download/v1/xxUSBSentinel.exe"
        Veracrypt   = "https://launchpad.net/veracrypt/trunk/1.26.15/+download/VeraCrypt%20Setup%201.26.15.exe"
    }

    foreach ($key in $FastURL.Keys) {
        $url = $FastURL[$key]
        $outputPath = "$toolsDirectory\$key.exe"

        try {
            Invoke-WebRequest -Uri $url -OutFile $outputPath -ErrorAction Stop
            Write-Output "Downloaded $key from $url to $outputPath"
        }
        catch {
            Write-Error "Failed to download $key from $url. $_"
        }
    }

    $LongURL = [ordered]@{
        Bleachbit = "https://download.bleachbit.org/BleachBit-4.6.2-portable.zip"
        Buskill   = "https://github.com/BusKill/buskill-app/releases/download/v0.7.0/buskill-win-v0.7.0-x86_64.zip"
        Clamav    = "https://www.clamav.net/downloads/production/clamav-1.4.1.win.x64.zip"
        Sdelete   = "https://download.sysinternals.com/files/SDelete.zip"
    }

    foreach ($key in $LongURL.Keys) {
        $url = $LongURL[$key]
        $downloadPath = "$Home\Downloads\$key.zip"
        $extractPath = "$toolsDirectory\$key"

        try {
            Invoke-WebRequest -Uri $url -OutFile $downloadPath -ErrorAction Stop
            Write-Output "Downloaded $key from $url to $downloadPath"
            Expand-Archive -Path $downloadPath -DestinationPath $extractPath -Force
            Write-Output "Extracted $key to $extractPath"
        }
        catch {
            Write-Error "Failed to download or extract $key from $url. $_"
        }
    }
}

function Show-Usage {
   Write-Host @"
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
    -anti               Disable and clear certain windows features and parameters for anti-forensics.
    -tools              Install anti-forensics tools.
    -disable            Only disable windows features without cleaning
    -clean              Only clean
"@
}

function Main {
    if ($all) {
        Start-Transcript -Path ".\logs_all.txt"
        Install-Tools
        Invoke-AntiForensics
        Stop-Transcript
    }
    elseif ($anti) {
        Start-Transcript -Path ".\logs_anti.txt"
        Invoke-AntiForensics
        Stop-Transcript
    }
    elseif ($tools) {
        Start-Transcript -Path ".\logs_tools.txt"
        Install-Tools
        Write-Output '[+] Done, reboot your system'
        Exit 0
        Stop-Transcript
    }
    elseif ($clean) {
        Start-Transcript -Path ".\logs_clean.txt"
        Invoke-Cleaning
        Stop-Transcript
    }
    elseif ($disable) {
        Start-Transcript -Path ".\logs_disable.txt"
        Invoke-Disable
        Stop-Transcript
    }
    else {
        Show-Usage
    }
}

Main
