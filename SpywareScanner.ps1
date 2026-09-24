#Requires -RunAsAdministrator
# Offline Spyware / Adware Heuristic Scanner for Windows 10/11
# Author: Custom script - Use at your own risk

$ErrorActionPreference = "SilentlyContinue"
$Host.UI.RawUI.WindowTitle = "Offline Spyware Scanner - Windows 10/11"

function Write-Color {
    param([string]$Text, [string]$Color = "White")
    Write-Host $Text -ForegroundColor $Color
}

function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Color "ERROR: This script must be run as Administrator!" "Red"
    Write-Color "Right-click PowerShell → Run as administrator, then run the script again." "Yellow"
    pause
    exit
}

Clear-Host
Write-Color "==============================================================" "Cyan"
Write-Color "     OFFLINE SPYWARE / ADWARE HEURISTIC SCANNER" "Cyan"
Write-Color "          Windows 10 & 11 - Fully Offline" "Cyan"
Write-Color "==============================================================" "Cyan"
Write-Host ""
Write-Color "This is a heuristic scanner. It is NOT a replacement for real antivirus." "Yellow"
Write-Color "False positives are possible. Review every item carefully before deleting." "Yellow"
Write-Host ""
Write-Color "Creating a System Restore Point is strongly recommended before continuing." "Magenta"
Write-Host ""

$continue = Read-Host "Do you want to continue with the scan? (Y/N)"
if ($continue -notmatch '^[Yy]') {
    Write-Color "Scan cancelled." "Yellow"
    exit
}

# ==================== KNOWN BAD NAMES (common spyware/adware) ====================
$KnownBadNames = @(
    "coolwebsearch","huntbar","wintools","look2me","gator","claria","whenucut","bargainbuddy",
    "searchprotect","conduit","genieo","dealply","babylon","asktoolbar","yontoo","opencandy",
    "installcore","downloadsponsor","superfish","lenovosupershield","couponserver","shopperpro",
    "websearch","toolbar","adware","spyware","keylogger","logger","monitor","stealer","rat",
    "backdoor","trojan","miner","cryptominer","coinminer","xmrig","systemupdate","browserupdate",
    "chromeupdate","softwareupdate","updater","helper","assistant","optimizer","cleanerpro",
    "pcoptimizer","speedup","boost","registryfix","driverupdater","antivirus","securitycenter"
)

# Suspicious paths (executables outside normal locations)
$SuspiciousPathPatterns = @(
    "\\Temp\\", "\\AppData\\Local\\Temp\\", "\\AppData\\Roaming\\", "\\AppData\\Local\\",
    "\\Users\\Public\\", "\\ProgramData\\", "\\Windows\\Temp\\", "\\Downloads\\"
)

$Findings = @()
$Counter = 0

function Add-Finding {
    param(
        [string]$Type,
        [string]$Name,
        [string]$Path,
        [string]$Details,
        [string]$ActionTarget  # What to delete/remove
    )
    $script:Counter++
    $script:Findings += [PSCustomObject]@{
        ID          = $script:Counter
        Type        = $Type
        Name        = $Name
        Path        = $Path
        Details     = $Details
        ActionTarget = $ActionTarget
    }
}

Write-Color "`n[1/6] Scanning Registry Run keys..." "Green"

# Registry Run / RunOnce
$RegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($reg in $RegPaths) {
    if (Test-Path $reg) {
        $props = Get-ItemProperty -Path $reg
        $props.PSObject.Properties | Where-Object {
            $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")
        } | ForEach-Object {
            $val = $_.Value
            $isSuspicious = $false
            $reason = ""

            # Check known bad names
            foreach ($bad in $KnownBadNames) {
                if ($_.Name -match $bad -or $val -match $bad) {
                    $isSuspicious = $true
                    $reason = "Matches known spyware/adware pattern: $bad"
                    break
                }
            }

            # Check unusual path
            if (-not $isSuspicious) {
                foreach ($pat in $SuspiciousPathPatterns) {
                    if ($val -like "*$pat*") {
                        $isSuspicious = $true
                        $reason = "Located in suspicious folder"
                        break
                    }
                }
            }

            # Flag almost everything outside Program Files / System32 for review
            if (-not $isSuspicious -and $val -notmatch "Program Files|System32|SysWOW64|Windows\\") {
                $isSuspicious = $true
                $reason = "Not in standard system location (review recommended)"
            }

            if ($isSuspicious) {
                Add-Finding -Type "Registry Run" -Name $_.Name -Path $reg `
                    -Details "$reason | Value: $val" -ActionTarget "$reg|$($_.Name)"
            }
        }
    }
}

Write-Color "[2/6] Scanning Startup folders..." "Green"

$StartupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($folder in $StartupFolders) {
    if (Test-Path $folder) {
        Get-ChildItem -Path $folder -Force | ForEach-Object {
            $isSus = $false
            $reason = "Startup item"
            foreach ($bad in $KnownBadNames) {
                if ($_.Name -match $bad) {
                    $isSus = $true
                    $reason = "Matches known bad name: $bad"
                    break
                }
            }
            # Flag non-Microsoft shortcuts / executables
            if ($_.Extension -match "\.exe|\.bat|\.cmd|\.vbs|\.js|\.lnk") {
                $isSus = $true
            }
            if ($isSus) {
                Add-Finding -Type "Startup Folder" -Name $_.Name -Path $_.FullName `
                    -Details $reason -ActionTarget $_.FullName
            }
        }
    }
}

Write-Color "[3/6] Scanning Scheduled Tasks..." "Green"

Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | ForEach-Object {
    $task = $_
    $actions = ($task.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "
    $isSus = $false
    $reason = ""

    foreach ($bad in $KnownBadNames) {
        if ($task.TaskName -match $bad -or $actions -match $bad) {
            $isSus = $true
            $reason = "Matches known spyware pattern: $bad"
            break
        }
    }

    # Tasks running from Temp / AppData / Public
    if (-not $isSus) {
        foreach ($pat in $SuspiciousPathPatterns) {
            if ($actions -like "*$pat*") {
                $isSus = $true
                $reason = "Runs from suspicious location"
                break
            }
        }
    }

    # Non-Microsoft authors with executable actions
    if (-not $isSus -and $task.Author -notmatch "Microsoft|Windows" -and $actions -match "\.exe|\.bat|\.cmd|\.vbs|\.ps1") {
        $isSus = $true
        $reason = "Non-Microsoft task with executable action (review)"
    }

    if ($isSus) {
        Add-Finding -Type "Scheduled Task" -Name $task.TaskName -Path $task.TaskPath `
            -Details "$reason | Action: $actions" -ActionTarget $task.TaskName
    }
}

Write-Color "[4/6] Scanning Services..." "Green"

Get-CimInstance Win32_Service | ForEach-Object {
    $svc = $_
    $isSus = $false
    $reason = ""

    foreach ($bad in $KnownBadNames) {
        if ($svc.Name -match $bad -or $svc.DisplayName -match $bad -or $svc.PathName -match $bad) {
            $isSus = $true
            $reason = "Matches known bad name: $bad"
            break
        }
    }

    if (-not $isSus -and $svc.PathName) {
        foreach ($pat in $SuspiciousPathPatterns) {
            if ($svc.PathName -like "*$pat*") {
                $isSus = $true
                $reason = "Service binary in suspicious location"
                break
            }
        }
    }

    # Services not from Microsoft with unusual paths
    if (-not $isSus -and $svc.PathName -notmatch "System32|SysWOW64|Program Files" -and $svc.StartMode -ne "Disabled") {
        $isSus = $true
        $reason = "Non-standard path (review recommended)"
    }

    if ($isSus) {
        Add-Finding -Type "Service" -Name $svc.Name -Path $svc.PathName `
            -Details "$reason | Display: $($svc.DisplayName) | State: $($svc.State)" `
            -ActionTarget $svc.Name
    }
}

Write-Color "[5/6] Scanning running processes..." "Green"

Get-Process | Where-Object { $_.Path } | ForEach-Object {
    $proc = $_
    $isSus = $false
    $reason = ""

    foreach ($bad in $KnownBadNames) {
        if ($proc.ProcessName -match $bad -or $proc.Path -match $bad) {
            $isSus = $true
            $reason = "Matches known spyware name: $bad"
            break
        }
    }

    if (-not $isSus) {
        foreach ($pat in $SuspiciousPathPatterns) {
            if ($proc.Path -like "*$pat*") {
                $isSus = $true
                $reason = "Running from suspicious folder"
                break
            }
        }
    }

    # Processes outside normal locations
    if (-not $isSus -and $proc.Path -notmatch "System32|SysWOW64|Program Files|Windows\\") {
        $isSus = $true
        $reason = "Unusual process location (review)"
    }

    if ($isSus) {
        Add-Finding -Type "Process" -Name $proc.ProcessName -Path $proc.Path `
            -Details "$reason | PID: $($proc.Id)" -ActionTarget $proc.Id
    }
}

Write-Color "[6/6] Scanning common spyware file locations..." "Green"

$ScanDirs = @(
    "$env:TEMP",
    "$env:LOCALAPPDATA\Temp",
    "$env:APPDATA",
    "$env:LOCALAPPDATA",
    "$env:PUBLIC",
    "$env:ProgramData"
)

foreach ($dir in $ScanDirs) {
    if (Test-Path $dir) {
        Get-ChildItem -Path $dir -Recurse -Include *.exe,*.dll,*.bat,*.cmd,*.vbs,*.js,*.scr -ErrorAction SilentlyContinue -Force |
        Where-Object { $_.Length -gt 10KB -and $_.Length -lt 50MB } |  # reasonable size filter
        ForEach-Object {
            $file = $_
            $isSus = $false
            $reason = ""

            foreach ($bad in $KnownBadNames) {
                if ($file.Name -match $bad) {
                    $isSus = $true
                    $reason = "Filename matches known spyware pattern: $bad"
                    break
                }
            }

            # Very new executables in Temp/AppData
            if (-not $isSus -and $file.CreationTime -gt (Get-Date).AddDays(-14) -and $file.DirectoryName -match "Temp|AppData") {
                $isSus = $true
                $reason = "Recently created executable in Temp/AppData"
            }

            if ($isSus) {
                Add-Finding -Type "Suspicious File" -Name $file.Name -Path $file.FullName `
                    -Details $reason -ActionTarget $file.FullName
            }
        }
    }
}

# ==================== RESULTS ====================

Write-Host ""
Write-Color "==================== SCAN COMPLETE ====================" "Cyan"
Write-Host ""

if ($Findings.Count -eq 0) {
    Write-Color "No suspicious items found based on heuristic rules." "Green"
    Write-Color "Note: This does not guarantee the system is clean." "Yellow"
    pause
    exit
}

Write-Color "Found $($Findings.Count) potentially suspicious item(s):" "Yellow"
Write-Host ""

$Findings | Format-Table -Property ID, Type, Name, Path -AutoSize -Wrap

Write-Host ""
Write-Color "Detailed list:" "Cyan"
foreach ($f in $Findings) {
    Write-Color "--------------------------------------------------" "DarkGray"
    Write-Color "[$($f.ID)] Type     : $($f.Type)" "White"
    Write-Color "    Name     : $($f.Name)" "White"
    Write-Color "    Path     : $($f.Path)" "Gray"
    Write-Color "    Details  : $($f.Details)" "Yellow"
}

Write-Host ""
Write-Color "==============================================================" "Cyan"
Write-Color "OPTIONS:" "Cyan"
Write-Color "  • Enter numbers separated by commas (e.g. 1,3,5) to delete selected items" "White"
Write-Color "  • Type 'ALL' to attempt removal of everything listed" "White"
Write-Color "  • Type 'N' or press Enter to exit without deleting anything" "White"
Write-Color "==============================================================" "Cyan"
Write-Host ""

$choice = Read-Host "Your choice"

if ([string]::IsNullOrWhiteSpace($choice) -or $choice -match '^[Nn]') {
    Write-Color "No changes made. Exiting." "Yellow"
    exit
}

$toRemove = @()
if ($choice -match '^[Aa][Ll][Ll]$') {
    $toRemove = $Findings
} else {
    $ids = $choice -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
    $toRemove = $Findings | Where-Object { $ids -contains $_.ID.ToString() }
}

if ($toRemove.Count -eq 0) {
    Write-Color "No valid items selected." "Yellow"
    exit
}

Write-Host ""
Write-Color "You selected $($toRemove.Count) item(s) for removal:" "Yellow"
$toRemove | ForEach-Object { Write-Host "  [$($_.ID)] $($_.Type) - $($_.Name)" }
Write-Host ""
$confirm = Read-Host "ARE YOU SURE you want to delete these? This cannot be easily undone! (YES to confirm)"

if ($confirm -ne "YES") {
    Write-Color "Deletion cancelled." "Yellow"
    exit
}

Write-Host ""
Write-Color "Starting removal..." "Magenta"

foreach ($item in $toRemove) {
    Write-Host ""
    Write-Color "Processing [$($item.ID)] $($item.Type) - $($item.Name)..." "Cyan"

    try {
        switch ($item.Type) {
            "Process" {
                $procId = [int]$item.ActionTarget
                $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
                if ($p) {
                    Stop-Process -Id $procId -Force
                    Write-Color "  → Process stopped." "Green"
                    Start-Sleep -Seconds 1
                    if (Test-Path $item.Path) {
                        Remove-Item -Path $item.Path -Force
                        Write-Color "  → File deleted: $($item.Path)" "Green"
                    }
                }
            }
            "Suspicious File" {
                if (Test-Path $item.ActionTarget) {
                    # Try to kill any process using the file
                    Get-Process | Where-Object { $_.Path -eq $item.ActionTarget } | Stop-Process -Force
                    Start-Sleep -Milliseconds 500
                    Remove-Item -Path $item.ActionTarget -Force
                    Write-Color "  → File deleted." "Green"
                }
            }
            "Startup Folder" {
                if (Test-Path $item.ActionTarget) {
                    Remove-Item -Path $item.ActionTarget -Force
                    Write-Color "  → Startup item removed." "Green"
                }
            }
            "Registry Run" {
                $parts = $item.ActionTarget -split '\|'
                $regPath = $parts[0]
                $valueName = $parts[1]
                Remove-ItemProperty -Path $regPath -Name $valueName -Force
                Write-Color "  → Registry value removed." "Green"
            }
            "Scheduled Task" {
                Unregister-ScheduledTask -TaskName $item.ActionTarget -Confirm:$false
                Write-Color "  → Scheduled Task removed." "Green"
            }
            "Service" {
                $svcName = $item.ActionTarget
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue
                # Note: full service deletion requires sc.exe delete and is more dangerous
                Write-Color "  → Service stopped and disabled (manual deletion of service may be needed)." "Yellow"
            }
        }
    }
    catch {
        Write-Color "  → ERROR: $($_.Exception.Message)" "Red"
    }
}

Write-Host ""
Write-Color "==============================================================" "Cyan"
Write-Color "Removal process finished." "Green"
Write-Color "Please restart your computer and run the scan again to verify." "Yellow"
Write-Color "==============================================================" "Cyan"
Write-Host ""
pause
