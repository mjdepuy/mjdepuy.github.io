# DefCon DFIR CTF 2018 - File Server

Welcome to the second of three installments of the DefCon DFIR CTF! This post will deal with the File Server image. A link to part 1 is [here](https://caffeinated4n6.blogspot.com/2018/12/defcon-dfir-ctf-2018.html" style="color: blue;).

### File Server - Basic

*1) What is the volume serial number of the only partition on the File Server Disk Image?*

There are a couple ways of doing this. The easiest is to open up the image in FTK Imager and look at the properties of the volume.

![](/assets/images/defcon_ctf_2018/fs_basic_1a.png)

Here it will show you the volume serial number already parsed out. Another way to see it is parsing the Volume Boot Record in a hex editor (HxD in my case). According to an article on [Wikipedia](https://en.wikipedia.org/wiki/Volume_boot_record) for the Volume Boot Record: 

`From decimal offset 72 to 79, an NTFS PBR contains the partition UUID volume id serial number.`

![](/assets/images/defcon_ctf_2018/fs_basic_1c.png)

![](/assets/images/defcon_ctf_2018/fs_basic_1b.png) 

From the photos above, you can see that decimal 72 is equivalent to 0x48. So starting at 0x48 and moving right 8 bytes, we get the volume ID. However, as we note from the FTK Imager picture, only the last four bytes of the ID is shown to the user. So remembering that Windows loves to store things in little endian, we get as our answer:

*Answer:* `C096-2465`

*2) What is the name of the examiner who made the Forensic Image?*

Using `ewfinfo` in the SIFT Workstation, you can get the properties of the image file. Another way to look is in FTK Imager under the Properties tab:

![](/assets/images/defcon_ctf_2018/fs_basic_2a.png)

*Answer:* `Professor Frink`

*3) Who cleared the security event log?*

This answer is a little hard to get at first because there are so many log entries around it. To make it more difficult for DFIR analysts to do their jobs, an attacker will attempt to clear the event log by generating a bunch of noise, thus pushing whatever malicious activity they were performing off the log file (size of the Security event log in this particular case is 20MB). In this case, they used a bunch of failed logon attempt events. That being said, in this case one could surmise that the `mpowers` user account was being used to conduct the attack based on the successful logon attempts around the same time as the log file is being cleared.

![](/assets/images/defcon_ctf_2018/fs_basic_3a.png)

*Answer:* `mpowers`

*4) What is the hostname of the computer?*

This value is located in the SYSTEM hive: `SYSTEM\ControlSet001\Control\ComputerName\ComputerName`.

![](/assets/images/defcon_ctf_2018/fs_basic_4a.png)

![](/assets/images/defcon_ctf_2018/fs_basic_4b.png)

*Answer:* `WIN-M5327EF98B9`

*5) When was the computer last shutdown? UTC Time In the format of Month/Day/Year Hour:Minute:Second in 24 hour time 1/1/2018 14:01:01*

You can find this also in the SYSTEM hive: `SYSTEM\CurrentControlSet\Control\Windows`.

![](/assets/images/defcon_ctf_2018/fs_basic_5a.png)

![](/assets/images/defcon_ctf_2018/fs_basic_5b.png)

*Answer:* `7/26/2018 10:16:16`

*6) What is the Current Build number of Windows on the File Server computer?*

Found in the SOFTWARE hive: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber`.

![](/assets/images/defcon_ctf_2018/fs_basic_6a.png)

*Answer:* `7601`

*7) What was mpowers user id?*

To find this, we can look in the SOFTWARE registry hive. This hive maintains a list of profile names and SIDs: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`.

This article on [ItProToday.com](https://www.itprotoday.com/windows-8/how-can-i-tell-which-user-has-which-sid) has a good short writeup about the key.

![](/assets/images/defcon_ctf_2018/fs_basic_7a.png)

![](/assets/images/defcon_ctf_2018/fs_basic_7b.png)

*Answer:* `1000`

*8) Which program did Max Powers last run through the GUI?*

This can be found through the UserAssist key located here: `NTUSER.dat\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`.

The UserAssist key keeps track of any application that the user launched by clicking on it through the GUI. A short description can be found [here](https://blog.didierstevens.com/programs/userassist/).

![](/assets/images/defcon_ctf_2018/fs_basic_8a.png)

![](/assets/images/defcon_ctf_2018/fs_basic_8b.png)

![](/assets/images/defcon_ctf_2018/fs_basic_8c.png)

*Answer:* `sub-win-x64_104.148.109.124_5682_3262.exe`

*9) When did Max Powers last open projections.zip? UTC TIme Day/Month/year Hour:Minute:Sec in 24 hour time 1/1/2018 15:20:11*

Normally you can view this in the RecentDocs key in the user's NTUSER.DAT file: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`. However, this key has been cleaned. As you might have noted from the previous post and answers, when it looks like something has been deleted we turn the the VSS image (if one exists)!

![](/assets/images/defcon_ctf_2018/fs_basic_9a.png)

![](/assets/images/defcon_ctf_2018/fs_basic_9b.png)

Copying the NTUSER.DAT file from the VSS image allows us to see the MRU list and the last time it was written to.

![](/assets/images/defcon_ctf_2018/fs_basic_9c.png)

![](/assets/images/defcon_ctf_2018/fs_basic_9d.png)

*Answer:* `8/7/2018 20:09:15`

*10) How many clusters are on the partition?*

FTK Imager gives this information to you when viewing the properties of the partition.

![](/assets/images/defcon_ctf_2018/fs_basic_10a.png)

You can also parse this from the Volume Boot Record. By dividing the total number of sectors by the number of clusters per sector, we get the total:

```0x6C3D7F8 == 113498104
113498104 / 8 = 13081343
```

A [tweet by Jared Atkinson](https://twitter.com/jaredcatkinson/status/590333209495244801?lang=en) gives further details on parsing the VBR.

*Answer:* `13081343`

### File Server - Advanced

*1) Where does the \VSS directory go?*

A reparse point is an NTFS object used to allow linking between two objects. While there are many different link types in Windows, in this particular case you can think of this as a Linux symlink. Reference [this SuperUser question for more information](https://superuser.com/questions/1297273/what-is-a-reparse-point-and-why-is-it-named-so).

To view the reparse point of a folder, you can click on the folder in FTK Imager and view the hex window. In this case it points to:

![](/assets/images/defcon_ctf_2018/fs_adv_1a.png)

*Answer:* `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1`

*2) When was the Volume Shadow Copy 1 created? Enter answer in UTC TIme in the following format 1/1/2018 13:11:11 Month/Day/Year 24 Hour Time*

With our VSS image still mounted, we can use `vshadowinfo` to tell us the date and time the copy was created.

![](/assets/images/defcon_ctf_2018/fs_adv_2a.png)

*QUICK NOTE: The time accepted on the CTF board at the time of this writing was the below answer. This answer is obtained using FTK Imager and looking at the properties of the System Volume Information folder. `vshadowinfo` will tell you 8/7/2018 20:13:26. This is probably due to the way both operating systems or the tools are handling rounding.*

*Answer:* `8/7/2018 20:13:25`

*3) Where did Max Powers login from?*

A couple good references for retrieving remote login information are [this post on PonderTheBits.com](https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/) and [this Microsoft TechNet post](https://social.technet.microsoft.com/Forums/ie/en-US/cb1c904f-b542-4102-a8cb-e0c464249280/is-there-a-log-file-for-rdp-connections?forum=winserverTS).

We are going to look at the `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` log. This event log details the login events after authentication has occured, which you can match with the `Security` event log. Knowing about when all this activity was occuring, we can see two event log entries for `mpowers`: one is a new connection, the other is a successful reconnection attempt. 

![](/assets/images/defcon_ctf_2018/fs_adv_3a.png)

![](/assets/images/defcon_ctf_2018/fs_adv_3b.png)

*Answer:* `74.118.138.195`

*4) What program was used to delete forensic artifacts?*

One great area to check are the Prefetch files located at `C:\Windows\Prefetch`. These files show you what programs were executed, how many times they've been executed, and will also tell you the last time it was executed based on the last write time of the file. However, by checking the registry key `SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters`, we can see that the `EnablePrefetch` key does not exist, meaning Prefetch is turned off. So where do we look next?

Program execution is also tracked in the UserAssist key. Microsoft thought it would be a good idea to perform a ROT13 on the UserAssist key, so we will need to undo that operation. CyberChef is the best tool to do this. Simply copy the list of applications into the input window, drag the ROT13 operation into the recipe window, then observe the output. As you notice, there is one application that stands out among the rest: PrivaZer. Performing a Google search tells us that we are dealing with a privacy application, with the ability to wipe logs and securely delete files. This seems like a good candidate for our answer.

![](/assets/images/defcon_ctf_2018/fs_adv_4a.png)

*Answer:* `PrivaZer`

*5) What is the name of the zip file that contains the M4Projects directory?*

One of the first steps upon obtaining this image was extracting the `$MFT`. Looking through the `$MFT` and finding no ZIP files, my next step was to check the VSS image. I ran a `ls -R | grep zip` and came across some interesting results, namely `FileServerShare.zip` and `project_0x03.zip`.

![](/assets/images/defcon_ctf_2018/fs_adv_5a.png)

![](/assets/images/defcon_ctf_2018/fs_adv_5b.png)

![](/assets/images/defcon_ctf_2018/fs_adv_5c.png)

![](/assets/images/defcon_ctf_2018/fs_adv_5d.png)

It appears they both had the same contents, but only one was the correct answer.

*Answer:* `FileServerShare.zip`

*6) What host was used to exfil the data?*

I got confused by this question at first. I put in the File Server's IP address, but that did not work. Using the IP that `mpowers` connected from did not work, either. I started looking around at what the machine may have connected to, starting first with web history. Ultimately, Chrome had the most data, so I pulled the Top Sites (what you see when you open a new tab in Chrome) and the History databases. Using [DB Browser for SQLite](https://sqlitebrowser.org/), I was able to determine that DropBox had been accessed from the File Server. Maybe this was the host they were talking about.

![](/assets/images/defcon_ctf_2018/fs_adv_6a_7a.png)

*Answer:* `www.dropbox.com`

*7) What is the url where the data was exfiled to?*

You can get this information from the same place as question 6.

*Answer:* `https://www.dropbox.com/request/51bpm0D7zHjRbfvuqGzt`

*8) What registry files did the attacker take? Please list them in alphabetical order with a space in between the names*

We cannot access the DropBox the files were exfiltrated to, and we do not have a Pcap of the traffic. What we do know is that RDP was used in the attack. The nice thing about RDP is that it leaves a cache of thumbnails that are created on the victim machine while it's in use.

![](/assets/images/defcon_ctf_2018/fs_adv_8a.png)

A great tool to parse these files with is [ANSSI-FR's](https://github.com/ANSSI-FR/bmc-tools) `bmc-tools.py` script. This will parse the RDP Bitmap Cache file and extract thumbnails into a defined directory. These images are not ordered in anyway, and there are a LOT of them, so it takes some time to go through.

![](/assets/images/defcon_ctf_2018/fs_adv_8b.png)

![](/assets/images/defcon_ctf_2018/fs_adv_8c.png)

With a medium degree of certainty, we can conclude that the `SAM` and `SYSTEM` hives were taken.

*Answer:* `SAM SYSTEM`

*9) What did the USN Journal get wiped with?*

We saw `PrivaZer` being used to wipe log files in our Google search from question 3. Further Googling shows us that it can, in fact, wipe artifacts from the `$USNJrnl` file. From their User Guide:

![](/assets/images/defcon_ctf_2018/fs_adv_9a.png)

*Answer:* `PrivaZer`

*10) What service did the attacker use to access this system?*

Based on our previous answer to how <code>mpowers</code> got on the machine, we can conclude that RDP was used.

*Answer:* `RDP`

### File Server - Expert

*1) What program extracted Mnemosyne.sys?*

A Google search for `Mnemosyne.sys` gave me a couple clues that it was related to memory. Further Googling showed that F-Response launches this driver when acquiring the physical memory of a target machine.

![](/assets/images/defcon_ctf_2018/fs_exp_1a.png)

![](/assets/images/defcon_ctf_2018/fs_exp_1b.png)

*Answer:* `f-response`

*2) What directory was wiped?*

For this, I probed around the `$MFT` for any files that were marked as `Not Active`. A lot of directories were unknown, but one directory stood out: `C:\M4Projects\projects_0x02`.

![](/assets/images/defcon_ctf_2018/fs_exp_2a.png)

Looking at FTK Imager also shows that these files were deleted.

![](/assets/images/defcon_ctf_2018/fs_exp_2b.png)

*Answer:* `C:\M4Projects\project_0x02`

*3) Who requested the data to be exfiled?*

We can visit the DropBox page we discovered in question #7 in the advanced section to see who requested the data.

![](/assets/images/defcon_ctf_2018/fs_exp_3a.png)

*Answer:* `Sideshow Bob`

*4) What is the email address of the person who uploaded the data to dropbox?*

Whoever uploaded the data to DropBox would have had to login, so it seems that, since RDP was used in the attack of this machine, we could check the output from the `bmc-tools.py` script. This took a while to go through every single image, but it is possible to pull enough out to confirm what the email address used to login to DropBox was.

![](/assets/images/defcon_ctf_2018/fs_exp_4a.png)

*Answer:* `snakepleskin@gmail.com`

Tune in next time for part 3: the Desktop image!

*Update 04 Feb 2022: Reader, there was no next post.*
