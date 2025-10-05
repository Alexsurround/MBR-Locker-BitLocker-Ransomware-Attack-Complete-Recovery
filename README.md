# MBR Locker + BitLocker Ransomware Attack: Recovery Guide

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Complete Recovery](https://img.shields.io/badge/Status-Complete%20Recovery-success)]()
[![Data Loss: 0%](https://img.shields.io/badge/Data%20Loss-0%25-brightgreen)]()

> **Case Study:** Complete documentation of a hybrid MBR Locker + BitLocker ransomware attack and successful recovery without paying ransom.

## 📋 Quick Summary

**Attack Details:**
- **Type:** MBR Locker + Screen Locker (NOT file-encrypting ransomware)
- **Device:** ASUS Laptop (LAPTOP-20DFKSG7)
- **Contact:** Telegram @skype911
- **Files Status:** ✅ NOT encrypted (only system blocked)
- **Recovery Time:** ~4 hours
- **Cost:** $0

**Key Finding:** Factory-enabled BitLocker was weaponized to create false impression of file encryption, while only MBR was modified.

---

## 🔴 Visual Evidence

### Attack Screen
![Ransom Screen](images/01-ransom-screen.jpg)
*Red screen displayed at boot demanding ransom via Telegram*

### BitLocker Status
![BitLocker Status](images/02-bitlocker-status.jpg)
*Live CD showing legitimate BitLocker protection triggered by MBR tampering*

### Disk Partitions
![Disk Structure](images/03-disk-partitions.jpg)
*Recovery partition intact, main partition locked by BitLocker (not ransomware)*

---

## 🎯 What Happened

### Attack Sequence
1. ❌ Malware gained admin privileges
2. ❌ Modified Master Boot Record (MBR)
3. ❌ Created fake ransom files (`info-Locker.txt`)
4. ✅ Factory BitLocker triggered (protection mechanism)
5. ✅ Files remained completely unencrypted

### The Confusion
```
User Perception: "My files are encrypted!"
Reality: Files are fine, only MBR is blocked
BitLocker Role: Legitimate security, NOT ransomware
```

---

## 🛠️ Recovery Process (TL;DR)

### Prerequisites
- Windows Live CD (Sergei Strelec or similar)
- BitLocker recovery key from Microsoft account
- USB drive for backup
- 4 hours of time

### Step-by-Step

**1. Boot from Live CD** (5 min)
```cmd
# Press F2/F12 at boot → Select USB
```

**2. Get BitLocker Key** (10 min)
- Visit: https://account.microsoft.com/devices/recoverykey
- Find your device recovery key
- Write it down

**3. Unlock BitLocker** (2 min)
```cmd
manage-bde -unlock C: -RecoveryPassword [YOUR-48-DIGIT-KEY]
```

**4. Verify Files** (5 min)
```cmd
dir C:\Users\YourUsername\Documents
notepad C:\Users\YourUsername\Documents\test.txt
```
✅ If files open normally → NOT encrypted!

**5. Backup Data** (30-60 min)
```cmd
xcopy C:\Users\YourUsername D:\Backup\ /E /H /I /Y
```

**6. Repair MBR** (5 min)
```cmd
bootrec /fixmbr
bootrec /fixboot
bootrec /rebuildbcd
bcdboot C:\Windows /s E: /f UEFI
```

**7. Manual Malware Cleanup** (30-60 min)
```cmd
# Search for malicious files
dir C:\Windows\Temp\*.exe /s
dir C:\Users\*\AppData\Local\Temp\*.exe /s
dir C:\ProgramData\*.exe /s /od

# Delete suspicious executables manually
# Check creation dates, names, digital signatures

# Remove ransom notes
del C:\info-Locker.txt /F /Q
for /r C:\ %i in (*info-Locker*) do del "%i" /F /Q

# Clean registry autostart
reg load HKLM\TEMP C:\Windows\System32\config\SOFTWARE
reg query "HKLM\TEMP\Microsoft\Windows\CurrentVersion\Run"
# Delete suspicious entries
reg unload HKLM\TEMP
```

**8. File Recovery with R-Studio** (1-2 hours)
⚠️ **Important:** Even though files weren't encrypted by ransomware, some were corrupted or partially damaged during the attack.

```
1. Download R-Studio: https://www.r-studio.com/
2. Scan drive C: for recoverable files
3. Look for:
   - Recently modified/deleted documents
   - Files with size mismatches
   - Corrupted Office documents
4. Recover to external drive
5. Verify recovered files integrity
```

**Why R-Studio was needed:**
- MBR modification caused some file system corruption
- Some files showed incorrect sizes or timestamps
- Quick format markers on certain sectors
- Recovered ~15GB of potentially affected documents

**9. Unhide Hidden Files** (15-30 min)
⚠️ **Critical Discovery:** Malware set most user files to HIDDEN attribute!

**Quick Method - Command Line:**
```cmd
REM Unhide all files on drive C:
attrib -h -s C:\Users\YourUsername\*.* /S /D

REM For all user folders:
attrib -h -s C:\Users\YourUsername\Documents\*.* /S /D
attrib -h -s C:\Users\YourUsername\Desktop\*.* /S /D
attrib -h -s C:\Users\YourUsername\Pictures\*.* /S /D
attrib -h -s C:\Users\YourUsername\Downloads\*.* /S /D
attrib -h -s C:\Users\YourUsername\Videos\*.* /S /D

REM This removes Hidden (-h) and System (-s) attributes
REM /S = subdirectories, /D = folders too
```

**Verify in Explorer:**
```
1. Open File Explorer
2. View → Options → Change folder and search options
3. View tab
4. Select "Show hidden files, folders, and drives"
5. Uncheck "Hide protected operating system files"
6. Apply to all folders
```

**Alternative - PowerShell Script (Faster):**
```powershell
# Run as Administrator
Get-ChildItem -Path "C:\Users\YourUsername" -Recurse -Force | 
  Where-Object {$_.Attributes -match 'Hidden'} | 
  ForEach-Object {$_.Attributes = 'Normal'}
```

**Why malware did this:**
- Makes users think files are deleted/encrypted
- Psychological pressure to pay ransom
- Files are actually intact, just hidden
- Common tactic in screen lockers

**Verification after unhiding:**
```cmd
REM Check file count before
dir C:\Users\YourUsername\Documents /A

REM After unhiding, count should increase
dir C:\Users\YourUsername\Documents
```

**10. Reboot** (2 min)
- Remove Live CD
- System should boot normally

**10. Deep Clean** (2-3 hours)
- Boot to Safe Mode
- Run Malwarebytes, Kaspersky KVRT, Dr.Web CureIt
- Check autostart, scheduled tasks
- Run `sfc /scannow`

**11. Final Verification** (30 min)
- Check all critical files open correctly
- Verify document integrity
- Test applications
- Ensure no residual malware

---

## ⚠️ Additional Recovery Notes

### File System Corruption Discovered

After unlocking BitLocker, discovered **partial file system corruption**:
- Some files showed incorrect sizes
- Timestamps were modified
- Several documents wouldn't open
- ~15GB of data needed recovery

**Root cause:** MBR modification + forced system crash damaged file allocation table entries.

### R-Studio Recovery Process

Used **R-Studio** (https://www.r-studio.com/) for deep recovery:

1. **Scan Phase** (45 min)
   - Full drive scan for lost/damaged files
   - Found 2,847 recoverable files
   - Identified corrupted directory entries

2. **Recovery Phase** (1-2 hours)
   - Recovered documents to external drive
   - Verified file integrity
   - Restored correct folder structure

3. **Results:**
   - ✅ Recovered: 98% of damaged files
   - ✅ Total recovered: ~15GB
   - ❌ Unrecoverable: ~300MB (permanently corrupted)

### Manual Malware Hunt

**Beyond automated scans, manual cleanup was critical:**

**Suspicious files found:**
```
C:\Windows\Temp\svchost32.exe          [Malware - Deleted]
C:\Users\*\AppData\Local\Temp\up.exe   [Malware - Deleted]
C:\ProgramData\WindowsUpdate\wu.exe    [Malware - Deleted]
C:\Users\*\AppData\Roaming\syst\*.dll  [Malware - Deleted folder]
```

**Registry persistence removed:**
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
  - "WindowsDefender" = "C:\ProgramData\...\wu.exe"  [Deleted]
  
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
  - "SystemUpdate" = "C:\Users\...\up.exe"  [Deleted]
```

**Scheduled tasks removed:**
- `\Microsoft\Windows\UpdateCheck` (fake task)
- `\SystemMaintenance` (malicious task)

**Why manual search was necessary:**
- Malware used legitimate-looking names
- Files had valid digital signatures (stolen)
- Some executables were packed/obfuscated
- Antivirus missed several variants

---

## 📊 Technical Analysis

### MBR Locker vs Crypto-Ransomware

| Feature | This Attack | Petya | NotPetya | CryptoLocker |
|---------|-------------|-------|----------|--------------|
| **MBR Modified** | ✅ | ✅ | ✅ | ❌ |
| **Files Encrypted** | ❌ | ❌ | ✅ | ✅ |
| **BitLocker Abuse** | ✅ | ❌ | ❌ | ❌ |
| **Recovery** | Easy | Medium | Impossible | Depends |
| **Threat Level** | 🟡 Low | 🟠 Medium | 🔴 Critical | 🟠 Medium |

### Why BitLocker Got Involved

```
1. ASUS Factory Setup
   └─ BitLocker enabled for security
   └─ TPM auto-unlock configured

2. Malware Infection
   └─ MBR modified
   └─ Boot integrity broken

3. BitLocker Protection Triggered
   └─ TPM detected tampering
   └─ Required recovery key
   └─ This PROTECTED your data!

4. User Confusion
   └─ Saw "BitLocker encrypted"
   └─ Assumed ransomware encryption
   └─ Reality: Security mechanism working correctly
```

---

## ⚠️ Important Warnings

### DO NOT:
- ❌ Pay the ransom (files aren't encrypted anyway)
- ❌ Disable BitLocker after recovery (it protected you)
- ❌ Attempt MBR repair before backing up data
- ❌ Connect to internet before cleaning malware

### DO:
- ✅ Get BitLocker recovery key FIRST
- ✅ Backup data before any repairs
- ✅ Run multiple antivirus scans
- ✅ Keep BitLocker enabled (your protection)
- ✅ Save recovery key to Microsoft account + print it

---

## 🛡️ Prevention

### Essential Security Measures

**1. Regular Backups** (CRITICAL)
```
Rule 3-2-1:
- 3 copies of data
- 2 different media types
- 1 copy offsite (cloud/remote location)
```

**2. Enable Ransomware Protection**
```
Settings → Update & Security → Windows Security
→ Virus & threat protection → Ransomware protection → ON
→ Controlled folder access → ON
```

**3. Keep BitLocker Enabled**
- Factory-enabled BitLocker = Good protection
- Always save recovery key to Microsoft account
- Print recovery key and store safely

**4. System Updates**
- Enable automatic Windows updates
- Keep antivirus definitions current

**5. Safe Behavior**
- Don't open suspicious email attachments
- Verify sender before clicking links
- Use only legitimate software
- Enable file extension display

---

## 📚 Resources

### Tools Used
- [Sergei Strelec WinPE](https://sergeistrelec.ru/) - Bootable Live CD
- [Rufus](https://rufus.ie/) - USB bootable creator
- [Malwarebytes](https://www.malwarebytes.com/) - Malware removal
- [Kaspersky KVRT](https://www.kaspersky.com/downloads/free-virus-removal-tool) - Virus removal tool

### Useful Links
- [Microsoft BitLocker Recovery Keys](https://account.microsoft.com/devices/recoverykey)
- [No More Ransom Project](https://www.nomoreransom.org/) - Free decryption tools
- [ID Ransomware](https://id-ransomware.malwarehunterteam.com/) - Identify ransomware type

### Related Research
- [Petya/NotPetya Analysis](https://www.welivesecurity.com/2017/06/27/petya-outbreak-heres-what-we-know/)
- [BitLocker Security](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/)

---

## 📖 Full Documentation

This repository contains detailed documentation in multiple languages:

- **English (Full):** [README_FULL_EN.md](README_FULL_EN.md) - Complete technical guide
- **Русский (Полная):** [README_FULL_RU.md](README_FULL_RU.md) - Полное руководство
- **Quick Start:** This document

---

## 🤝 Contributing

Encountered similar ransomware? Have additional recovery methods? Contributions welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add recovery method'`)
4. Push to branch (`git push origin feature/improvement`)
5. Open a Pull Request

---

## ⚖️ Legal Disclaimer

This documentation is for **educational and recovery purposes only**. 

- Information provided to help victims recover their data
- Not intended to aid in creating malware
- Always report ransomware attacks to law enforcement
- Never pay ransoms (funds terrorism and future attacks)

---

## 📞 Support

- **Issues:** Use GitHub Issues for questions
- **Security Reports:** Email privately for vulnerability reports
- **Emergency:** Contact local law enforcement for active attacks

---

## 📄 License

This documentation is released under MIT License. Free to use, modify, and distribute with attribution.

```
MIT License - Copyright (c) 2025
```

---

## 🙏 Acknowledgments

- **No More Ransom Project** - Global ransomware decryption initiative
- **Sergei Strelec** - Excellent WinPE Live CD
- **Malware research community** - Ongoing analysis and tools
- **Microsoft Security** - BitLocker documentation

---

## 📈 Statistics

- **Recovery Success Rate:** 100% (system fully operational)
- **Data Loss:** ~0.3% (~300MB of 100GB user data)
- **Time to Recovery:** ~8 hours total
  - BitLocker unlock: 10 min
  - Data backup: 1 hour
  - MBR repair: 10 min
  - Malware cleanup: 2 hours
  - R-Studio recovery: 2 hours
  - System verification: 2 hours
- **Cost:** $0 (R-Studio free trial used)
- **Files Encrypted by Ransomware:** 0
- **Files Corrupted by MBR Attack:** ~2,847
- **Successfully Recovered:** 98%

---

**Remember:** Most "encrypted files" ransomware attacks are actually just screen lockers. Always investigate with Live CD before assuming the worst!

**Stay safe, backup regularly, and never pay ransoms.**

---

*Last Updated: October 2025*
*Case Study: LAPTOP-20DFKSG7 | Attack Vector: MBR Locker | Recovery: Complete*
