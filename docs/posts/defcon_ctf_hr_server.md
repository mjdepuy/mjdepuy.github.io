# DefCon DFIR 2018 - HR Server

While not able to attend DefCon this year, I saw a tweet by David Cowen [@HECFBlog](https://twitter.com/HECFBlog) about a DFIR-flavored CTF to be held. After reading from people who attended how fun it was, I decided to give it a go.

There are 3 images. The first image is an HR server, the second is a file server, and the third is a desktop. There will be 3 posts, one for each image. [Here is a link to his blogpost](https://www.hecfblog.com/2018/08/daily-blog-451-defcon-dfir-ctf-2018.html) so you can download the images and take a look for yourself.

### HR Server - Basic
*1) Which software was used to image the HR Server?*

This is pretty easy to do. The [SANS SIFT Workstation](https://digital-forensics.sans.org/community/downloads") comes with `libewf`. Using `ewfinfo`, we can look at the imaging information of the E01 file.

![](/assets/images/defcon_ctf_2018/hr_basic_1a.jpg)

*Answer:* `X-Ways Forensics`

*2) What version of the software was used to image the HR server?*

Looking at the previous screenshot, we can see the version of the software that was used.

*Answer:* `19.6`

*3) What is the file name that represent MFT Entry 168043?*

To perform this task, we can use FTK Imager to extract the $MFT file from the HR Server image.

![](/assets/images/defcon_ctf_2018/hr_basic_3a.jpg)

Once extracted, use Eric Zimmerman's [MFTEcmd](https://ericzimmerman.github.io/) tool to parse the file out to a CSV. Then, search the CSV for the entry number 168043.

![](/assets/images/defcon_ctf_2018/hr_basic_3b.jpg)

*Answer:* `pip3.7.exe`

*4) What is the MFT Entry number of the following file? \xampp\mysql\bin\mysql.exe*

Same as the last question, only we need to search for the filename instead of the entry number.

![](/assets/images/defcon_ctf_2018/hr_basic_4a.jpg)

*Answer:* `115322`

*5) What is the MFT Attribute ID of the named $J data attribute for the MFT Entry with a file name of $UsnJrnl?*

This attribute is not parsed out by MFTEcmd and is a bit more difficult and will require a little math. In the MFT, each record is 1024 bytes in length. The entry number for the $UsnJrnl is 108606. We can multiply that by 1024 bytes and get the offset in the MFT where the record lies. Let's take a look using our handy hex editor! (We are going to use [HxD](https://mh-nexus.de/en/hxd/")) It has a feature that will allow us to plug in the offset and take us directly to the beginning of the file's record.

```
108606 * 1024 = 111212544
Convert to hex: 111212544 == 6A0F800
```
![](/assets/images/defcon_ctf_2018/mft_hxd_urnjrnl.jpg)

Here is the record we are looking for. Highlighted in red, you will see the bytes `30 00`. This is the Attribute ID we are looking for. Remember, Windows like little endian, so the answer here is:

*Answer:* `3`

*6) At 2018-08-08 18:10:38.554 (UTC) what was the IP address of the the client that attempted to access SMB via an anonymous logon?*

A good place to look for SMB traffic given a hard drive image is the SMB Security event log. Here, we can look for attempted SMB session authentications. Using FTK Imager, we can pull out the Security event log and look for SMB session authentication errors (event code 551). Since I am on the west coast, my timezone puts me at UTC-7, hence the timestamp difference in the picture.

![](/assets/images/defcon_ctf_2018/hr_basic_6a.jpg)

*Answer:* `80.81.110.50`

*7) What was the name of the batch file saved by mpowers?*

As evidenced by the SANS Windows Forensics poster, a good place to look for recently accessed files is the `OpenSaveMRU` key in the user's `NTUSER.dat`. This key tracks the opening or saving of any file from the Windows shell dialog box by file type. One of the best tools to parse registry files is Eric Zimmerman's [Registry Explorer](https://ericzimmerman.github.io/). Once we open the `NTUSER.dat` file, we navigate to the following path: `NTUSER.dat\Software\Microsoft\Windows\CurrentVersion\Explorer\Comdlg32\OpenSavePidMRU\bat`.

![](/assets/images/defcon_ctf_2018/hr_basic_7a.jpg)

Here we find the `MRUListEx` subkey. This tells us in which order the files were opened, with the latest file being the first entry in the list. Here we see that subkey "0" was the last to be opened. Clicking on subkey 0, we get the file `update_app.bat`. The answer needs a full filepath to be satisfied, so we can use the file name to search the MFT with and get the full filepath.

![](/assets/images/defcon_ctf_2018/hr_basic_7b.jpg)

*Answer:* `c:\Production\update_app.bat`

*8) What is the name of the hr management application that hosts a web server?*

Perusing the `Program Files` directory, we can see that `OrangeHRM` stands out in the list. Google confirms that this is an HR solution.

*Answer:* `OrangeHRM`

*9) What was the public url for the HR system’s portal?*

First, we need to get the IP address of the server. Easiest way to do this is to look at the `SYSTEM` registry hive. Using that information, we can comb the OrangeHRM server's `access.log` file for the IP address and the URL for the login page.

![](/assets/images/defcon_ctf_2018/hr_basic_8a.jpg)

![](/assets/images/defcon_ctf_2018/hr_basic_8b.jpg)

*Answer:* `http://74.118.139.108/symfony/web/index.php/auth/login`

*10) What is name of the file that had a change recorded with an update sequence number of 368701440?*

`MFTEcmd` parses out the update sequence number from the MFT for us. Searching for the number, we get:

*Answer:* `Microsoft-WIndows-SMBServer%4Security.evtx`

*11) What is the name of the deleted file with a reference number of 12947848928752043?*

This one stumped me for a good while. Google does not return many results when look for `MFT file reference number`. Recently (5 December 2018), David Cowen on the Forensic Lunch regularly hosts a "Test Kitchen". In this episode, he was looking at a file that is sometimes resident on Windows 7 machines called the `syscache.hve`. This file houses a `_FileID_` attribute that is very similar to a file reference number. This gave me the idea to look at the Windows Internals books (6e. Part 2), specifically at the MFT section. A subsection on File Record Numbers tell us that a number consists of 8 bytes, or 64 bits. The first 16 bits is the Sequence Number. The last 48 bits are the MFT number. That leads us to believe that the file reference number is a decimal representation of the sequence and entry numbers OR'd together. To convert the decimal reference number to a sequence number and MFT entry number, we must first convert the given reference number to hex. The hex number is only 7 bytes long, so we must prepend a 00 to the front. Then take the first two bytes and the last 6 bytes, and convert each to decimal. You now have the sequence and MFT entry numbers.

```
12947848928752043 == 0x2E00000000F1AB
0x002E00000000F1AB --> 0x002E and 0x00000000F1AB --> 46 and 61867
```
The sequence number will need to have 1 added to it, as the entries parsed out of the MFT start at 1 instead of zero, so we are really looking for sequence number 47. 

![](/assets/images/defcon_ctf_2018/hr_basic_11a.jpg)

*Answer:* `_MEI78882`

### HR Server - Advanced

*1) At 2018-07-30 22:31:33 UTC which user was logged in under, what was the logon type (integer), and the logon process name?*

At first one would think that this question should fall under the basic category, right? Look at the Security event log at the specified time for a `4624` event! Well hold on. Looking at the log, the very first entry is an `1102`, which means someone cleared the logs! The key here is we need to go back in time. Good thing Windows provides a way to do just that!

Volume Shadow Copies are a forensic analyst's bread and butter during an investigation. Using these, a forensic analyst could potentially go to a time just before the computer was infected. It is also useful for recovering files that may have been tampered with or otherwise corrupted.

The tool we will use to recover the Volume Shadow Copies is `libvshadow`. While you could go through the tedium of using the Windows version, a pre-installed version is already installed on the SANS SIFT Workstation. Booting into the workstation, we will first need to know where the NTFS volume actually lies in the image.

```
sudo su
mmls IMAGE.e01
```

![](/assets/images/defcon_ctf_2018/hr_adv_1a.jpg)

We see the volume is offset by 0001026048\*512 bytes from the beginning. With that in mind, we can mount the image, and collect information about the Volume Shadow Copies.

```
ewfmount <LOCATION OF E01 IMAGE> /mnt/ewf
vshadowinfo -o 525336576 /mnt/ewf/ewf1
vshadowmount -o 525336576 /mnt/ewf/ewf1 /mnt/vss
mount -o ro,loop,show_sys_files,streams_interface=windows /mnt/vss/vss1 /mnt/shadow_mount
```
![](/assets/images/defcon_ctf_2018/hr_adv_1b.jpg)

We can now view the contents of the Volume Shadow Copy and pull the event log by changing directory to `C:\Windows\System32\winevt\Logs\Security.evtx`. Copy that file to a shared folder or your Windows host and view it.

We are looking for a 4624 event that happened at `2018-07-30 22:31:33 UTC`.

![](/assets/images/defcon_ctf_2018/hr_adv_1c.jpg)

*Answer:* `mpowers - 10 - User32 - 74.118.138.195`

*2) At 2018-07-27 02:42:43 (UTC), what is the name of the task that was started?*

This question builds off the previous one. We again will need to visit the Volume Shadow Copy we looked at earlier. The keyword here is "task". Looks like we are attempting to find a Scheduled Task, so the event log to pull is under `C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx`. Task Started events have the code `100`. So look for a 100 at the time in question.

*Answer:* `\Throw Taco`

*3) Which IP address was accessing the OrangeHRM portal via Chrome 68.0.3440.84?*

This question will have us revisit the `access.log` file resident in `C:\Program Files\OrangeHRM\4.1\apache\logs\`. I have a shared folder between my Windows host and SIFT, so I exported the access.log file and used `cat access.log | grep "Chrome 68.0.3440.84"` to find the resulting IP.

*Answer:* `74.118.139.108`

*4) What version of Apache was being used?*

View the file `C:\Program Files\OrangeHRM\4.1\apache\CHANGES.txt`. Look at the latest changes (top of the file).

*Answer:* `2.4`

*5) What is the integer representation for the reason code given a USN V2 record where the record’s reason flags have the following: USN_REASON_CLOSE | USN_REASON_DATA_EXTEND | USN_REASON_FILE_CREATE*

The `$UsnJrnl` is a file that keeps track of changes made to all files and folders on the volume. The first tool that came to mind was Harlan Carvey's `usnj.pl` script. I am not going to parse the file, but instead examine the code that will parse out the reason codes and display them in human-readable format.

```
USN_REASON_CLOSE: 0x80000000
USN_REASON_DATA_EXTEND: 0x00000002
USN_REASON_FILE_CREATE: 0x00000100
```
To get the integer representation, you must add (read: OR) them together, then convert that hex number to decimal.

```
0x80000000
0x00000002
0x00000100
----------
0x80000102 --> 2147483906
```

![](/assets/images/defcon_ctf_2018/hr_adv_5a.jpg)

*Answer:* `2147483906`

### HR Server - Expert

*1) What was the top communicating IP address with the web server?*

Once again, we look at the previous `access.log` file. The easiest way to do this is going into SIFT (or any Linux machine) and running AWK and stats over it.

`cat access.log | awk -F ' ' '{ print $1 }' | sort | uniq -c | sort -n`

![](/assets/images/defcon_ctf_2018/hr_exp_1a.jpg)

*Answer:* `74.118.138.195`

*2) How many requests were made to the web server where the requested url contained a wget command within in?*

Utilizing a similar technique from the last question, the following command line gives us the answer:

`cat access.log | grep wget | wc -l`

![](/assets/images/defcon_ctf_2018/hr_exp_2a.jpg)

*Answer:* `101`

### End of HR Server questions

The next section will consist of the File server questions and answers.

Here is a [link](https://caffeinated4n6.blogspot.com/2019/01/defcon-dfir-ctf-2018-file-server_20.html) to the next blog post.
