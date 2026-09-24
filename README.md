# Offline Spyware Scanner (Windows 10/11)

A pure offline PowerShell heuristic scanner that searches for common spyware, adware, and suspicious persistence mechanisms on Windows 10 and Windows 11.

**No internet connection required.**

---

## ⚠️ Important Disclaimer

This is a **heuristic scanner**, **not** a full antivirus or anti-malware product.

- It can produce **false positives**.
- It does **not** replace Windows Defender, Malwarebytes, or any professional security tool.
- Always review every detected item carefully before deleting anything.
- Create a **System Restore Point** before running the script.
- Use at your own risk. The author is not responsible for any data loss or system issues.

---

## Features

- Fully offline (no cloud lookups, no signature downloads)
- Scans:
  - Registry Run / RunOnce keys (HKLM + HKCU)
  - Startup folders
  - Scheduled Tasks
  - Windows Services
  - Running processes from unusual locations
  - Common spyware/adware file and process names
  - Suspicious executables in Temp / AppData / Public folders
- Lists all findings with numbers
- Interactive removal: choose individual items, multiple items, or all
- Safe removal workflow (stops processes → deletes files → cleans registry/tasks)
- Colored console output for easy reading
- Requires Administrator privileges

---

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later (built-in)
- Administrator rights

---

## How to Use

### Method 1 – Right-click (easiest)

1. Download `SpywareScanner.ps1`
2. Right-click the file → **Run with PowerShell**
3. If you get an execution policy error, use Method 2

### Method 2 – PowerShell as Administrator (recommended)

1. Press `Win + X` → choose **Windows PowerShell (Admin)** or **Terminal (Admin)**
2. Navigate to the folder containing the script:
   ```powershell
   cd "C:\Path\To\Script"
   ```
3. Temporarily allow the script to run:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   ```
4. Run the scanner:
   ```powershell
   .\SpywareScanner.ps1
   ```

---

## What Happens During the Scan

1. The script checks that it is running as Administrator.
2. It scans the locations listed above.
3. It shows a numbered list of potentially suspicious items.
4. You can:
   - Enter numbers (example: `1,3,5`) to remove selected items
   - Type `ALL` to attempt removal of everything listed
   - Type `N` or press Enter to exit without making changes
5. You must type `YES` to confirm deletion.

---

## Recommendations

- Create a System Restore Point before running.
- After cleaning, restart your computer and run the scanner again.
- For better protection, also run Windows Defender:
  ```powershell
  Start-MpScan -ScanType FullScan
  ```
- Consider using a dedicated tool such as Malwarebytes or AdwCleaner for a second opinion.

---

## Limitations

- Relies on heuristics and a hardcoded list of common spyware/adware names.
- Will not detect brand-new or highly obfuscated malware.
- Does not scan the entire hard drive byte-by-byte.
- Service removal only stops and disables the service (full deletion is more invasive and left for manual action).
- Browser extensions are not currently checked.

---

## Safety Notes

- Never run this script on a production server without testing.
- Do not blindly delete everything it finds.
- If you are unsure about an item, research the name/path before removing it.
- Keep Windows Defender (or another real-time antivirus) enabled.

---

## License

This script is provided as-is for educational and personal use.  
You are free to modify and share it. No warranty is given.

---

**Stay safe.**  
If you find bugs or have suggestions, feel free to improve the script.