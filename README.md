# Jlaive - What is it
Jlaive is an obfuscator engine which basically converts a .NET exe to obfuscated .bat file for AV evasion.

# Jlaive-Deobfuscator
This is a project I thought of doing after being inspired by the [Get-UnJlaive](https://github.com/Dump-GUY/Get-UnJlaive) project written in powershell.

The Get-UnJlaive is written in powershell and its goal is to recover the original executable before it was converted to an obfuscated batch file.
The issue is that, if the original executable was waiting for a user action to happen, it would fail to recover it.  Also, it was not extracting all the intermediate files that were being created nor it deobfuscated the .bat file.  
Truth is, there was no need to provide all the intermediate files but I thought it would be nice to somehow extract them all:)

So, here is my attempt of writing a script in python that:  
- Deobfuscates the .bat file to a more readable form
- Recovers all the .cs files created.
- Recovers all the .ps1 files created.
- Recovers the keys, ivs and encrypted blocks and decrypts them, providing the intermediate .exe files.
- Recovers the original executable before being converted to that obfuscated .bat file.
