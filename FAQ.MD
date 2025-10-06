# Frequently Asked Questions (FAQ)

## General Questions

**Q: Is this a real case or theoretical?**
A: Real case. ASUS laptop LAPTOP-20DFKSG7, October 2025.

**Q: Were files actually encrypted?**
A: NO. Only MBR was modified. Files were hidden with Hidden attribute.

**Q: Should I pay the ransom?**
A: NEVER. Files aren't encrypted, just blocked/hidden.

**Q: How long does recovery take?**
A: 10 hours total, but system is usable after 2-3 hours.

## BitLocker Questions

**Q: How do I get my BitLocker recovery key?**
A: https://account.microsoft.com/devices/recoverykey

**Q: I don't have the key, can I still recover?**
A: If you never saved it, data may be unrecoverable. Try all Microsoft accounts first.

**Q: Should I disable BitLocker after recovery?**
A: NO! BitLocker protected your data. Keep it enabled.

## Hidden Files Questions

**Q: Why did malware hide files instead of encrypting?**
A: Psychological tactic. Faster, harder to detect, same panic effect.

**Q: Will antivirus detect hidden files as malware?**
A: No, Hidden attribute is legitimate Windows feature.

## Permissions Questions

**Q: Why can't I install programs after recovery?**
A: Malware damaged ACL (permissions) on Program Files.

**Q: Is it safe to reset all permissions?**
A: Yes, for Program Files, ProgramData. NOT for C:\Windows without backup.

**Q: How long does permission fix take?**
A: 30-60 minutes depending on number of files.

## Recovery Questions

**Q: Do I need R-Studio?**
A: Only if files are corrupted. In this case, ~3% needed recovery.

**Q: Can I do this without technical skills?**
A: Yes, follow step-by-step commands. Copy-paste carefully.

**Q: What if I don't have Live CD?**
A: Download Sergei Strelec WinPE: https://sergeistrelec.ru/

## Prevention Questions

**Q: How do I prevent this in future?**
A: Regular backups (3-2-1 rule), Windows updates, ransomware protection enabled.

**Q: Should I keep BitLocker enabled?**
A: YES. It's good security. Just save recovery key safely.

**Q: Best antivirus?**
A: Windows Defender + Malwarebytes free is sufficient. Keep updated.
