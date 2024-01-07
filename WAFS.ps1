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

[CmdletBinding()]
param (
    [switch]$all,
    [switch]$anti,
    [switch]$tools
)

function anti {

    Write-Output '[+] Anti-Forensics Script'

    $PathsToRemove = @{
        'ChromeCache'           = "$Home\AppData\Local\Google\Chrome\User Data\Default\Cache"                                   # Clean Chrome cache
        'ChromeHistory'         = "$Home\AppData\Local\Google\Chrome\User Data\Default\History"                                 # Clean Chrome history
        'ChromeSessionRestore'  = "$Home\AppData\Local\Google\Chrome\User Data\Default"                                         # Clean Chrome Session Restore
        'EdgeCache'             = "$Home\AppData\Local\Packages\microsoft.microsoftedge_*\AC\MicrosoftEdge\Cache"               # Clean Edge cache
        'IEHistory'             = 'HKCU:\Software\Microsoft\Internet Explorer\TypedURLs'                                        # Clean Edge / Internet Explorer history
        'IEWebCache'            = "$Home\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat"                               # Clean Edge / Internet Explorer history
        'FirefoxCache'          = "$Home\AppData\Local\Mozilla\Firefox\Profiles\*.default\Cache"                                # Clean Firefox cache
        'FirefoxHistory'        = "$Home\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\places.sqlite"                      # Clean Firefox history
        'FirefoxSessionRestore' = "$Home\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\sessionstore.js"                    # Clean Firefox Session Restore
        'IECache'               = "$Home\AppData\Local\Microsoft\Windows\INetCache\IE"                                          # Clean Internet Explorer cache
        'IECacheStorage'        = "$Home\AppData\Local\Microsoft\Internet Explorer\CacheStorage"                                # Clean Internet Explorer cache
        'IESessionRestore'      = "$Home\AppData\Local\Microsoft\Internet Explorer\Recovery"                                    # Clean Internet Explorer Session Restore
        'LastVisitedMRU'        = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU'        # Clean Last-Visited MRU
        'OpenSaveMRU'           = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU'           # Clean OpenSaveMRU
        'PlugAndPlayLogs'       = "C:\Windows\INF\setupapi.dev*\"                                                               # Clean Plug and Play Logs
        'Prefetch'              = "C:\Windows\Prefetch"                                                                         # Clean Prefetch
        'RecentItems'           = "$HOME\AppData\Roaming\Microsoft\Windows\Recent"                                              # Clean Recent Items
        'RecentDocs'            = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'                         # Clean Recent Items
        'RunMRU'                = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'                             # Clean Run Command history
        'ShadowCopies'          = 'HKLM:\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToBackup'                       # Disable Shadow Copies
        'ShellBags'             = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell'                      # Clean ShellBags
        'ShellNoRoam'           = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\ShellNoRoam'                # Clean ShellBags
        'ShellWow6432'          = 'HKCU:\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\'         # Clean ShellBags
        'Simcache'              = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\'                      # Clean Simcache
        'SRUDB'                 = "C:\Windows\System32\sru\SRUDB.dat"                                                           # Clean System Resource Usage Monitor database
        'TempFiles'             = "C:\Windows\temp\*"                                                                           # Clean Temp files
        'Thumbcache'            = "$Home\AppData\Local\Microsoft\Windows\Explorer\thumbcache*.db\"                              # Clean Thumbcache
        'USBHistory'            = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'                                                 # Clean USB history
        'USBEnum'               = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB'                                                     # Clean USB history
        'UserAssist'            = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\'                        # Clean UserAssist
        'VPNCache'              = 'HKLM:\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache'                             # Clean VPN cache
        'TimelineDB'            = "$Home\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db"                           # Clean Windows Timeline DB
        'PowerShellHistory'     = "$HOME\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"       # Clean Powershell history
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
        Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' | New-ItemProperty -Name 'NtfsDisableLastAccessUpdate' -Value "1" -PropertyType DWORD -Force >$null
        fsutil behavior set disablelastaccess 3 >$null

        # Disable Prefetch
        Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' | New-ItemProperty -Name 'EnablePrefetcher' -Value "0" -PropertyType DWORD -Force >$null
        Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' | New-ItemProperty -Name 'EnableSuperfetch' -Value "0" -PropertyType DWORD -Force >$null

        # Clean RecycleBin
        Clear-RecycleBin -Force 2>$null

        # Disable previous Shadow Copies
        Get-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\' | New-ItemProperty -Name 'DisableLocalPage' -Value "1" -PropertyType DWORD -Force >$null

        # Clean Shadow Copies
        vssadmin delete shadows /All >$null

        # Disable ShellBags
        Get-Item -Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell' | New-ItemProperty -Name 'BagMRU Size' -Value "1" -PropertyType DWORD -Force >$null

        # Disable UserAssist
        Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' | New-ItemProperty -Name 'Start_TrackProgs' -Value "0" -PropertyType DWORD -Force >$null
        Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\' | New-ItemProperty -Name 'Start_TrackEnabled' -Value "0" -PropertyType DWORD -Force >$null

        # Disable Windows Event logs
        Stop-Service -Name EventLog -Force 2>$null
        Set-Service EventLog -StartupType Disabled

        # Clean Windows Event logs
        wevtutil el | Foreach-Object { wevtutil cl "$_" } 2>$null

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


function tools {

    Write-Output '[+] Tools Script'
    New-Item -Path "$HOME" -Name "Tools" -ItemType Directory >$null

    # Download and install some programs
    $FastURL = [ordered]@{
        DSP         = "https://github.com/LloydLabs/delete-self-poc/releases/download/v1.1/ds_x64.exe"
        Exif        = "https://www.two-pilots.com/colorpilot.com/load/exif_64.exe"
        Timestomper = "https://github.com/slyd0g/TimeStomper/blob/master/Release/TimeStomper.exe"
        USBSentinel = "https://github.com/thereisnotime/xxUSBSentinel/releases/download/v1/xxUSBSentinel.exe"
        Veracrypt   = "https://kumisystems.dl.sourceforge.net/project/veracrypt/VeraCrypt%201.26.7/Windows/VeraCrypt%20Setup%201.26.7.exe"
    }

    foreach ($key in $FastURL.Keys) {
        $url = $FastURL[$key]
        $outputPath = "$Home\Tools\$key"

        try {
            Invoke-WebRequest -Uri $url -OutFile $outputPath -ErrorAction Stop
            Write-Output "Downloaded $key from $url to $outputPath"
        }
        catch {
            Write-Error "Failed to download $key from $url. $_"
        }
    }


    $LongURL = [ordered]@{
        Bleachbit = "https://www.bleachbit.org/download/file/t?file=BleachBit-4.6.0-portable.zip"
        Buskill   = "https://github.com/BusKill/buskill-app/releases/download/v0.7.0/buskill-win-v0.7.0-x86_64.zip"
        Clamav    = "https://www.clamav.net/downloads/production/clamav-1.1.1.win.x64.zip"
        Sdelete   = "https://download.sysinternals.com/files/SDelete.zip"
    }

    foreach ($key in $LongURL.Keys) {
        $url = $LongURL[$key]
        $downloadPath = "$Home\Downloads\$key.zip"
        $extractPath = "$Home\Tools\$key"

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

function usage {
    Write-Output "
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
    elseif ($anti) {
        Start-Transcript -Path ".\logs_anti.txt"
        anti
        Stop-Transcript
    }
    elseif ($tools) {
        Start-Transcript -Path ".\logs_tools.txt"
        tools
        Write-Output '[+] Done, reboot your system'
        Exit 0
        Stop-Transcript
    }
    else {
        usage
    }
}
main
