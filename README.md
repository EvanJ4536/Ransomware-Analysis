# Ransomware Analysis

## Introduction
This report analyzes a file: Statement009840913.scr, an apparent ransomware variant identified during a recent security incident at my office.  This report aims to outline my findings in static and behavioral analysis.  

Here is a Threat Graph I made on VirusTotal: https://www.virustotal.com/graph/g85c720a1b4c546b3bf0d8170333b2b99a7c42e844c5c47c5af8b6d614bbe8c2e  

## Overview
| Basic Information |  |
| ----------------- | ---------------- |
| **Name** | Statement009840913.scr |
| **Family** | Yanluowang? |
| **Date Detected** | 9/14/2024 |
| **SHA-256** | df44a4e931a572d24413fa0611001b57d595a984b14220f2996e83b582a2d901 |
| **File Type**  | Portable Executable |
| **Size**  | 51,327,578 bytes  |

 At the date of detection, this file had never been uploaded to VirusTotal, and was detected by 4 out of 72 antivirus. 

 ## Infection Vector

 This file was received in a Phishing email sent to our support department.  The attacker claimed to be a customer that was over charged. They sent an email with an attachment of a "screenshot of their bank statement" in the form of an Executable Screensaver format.  The attachment had the icon of a pdf file and requested administrator access when executed.  

__________________________________________________________________________________________________________  

 ## Behavioral Analysis By VirusTotal  

 ### Matches YARA Rule for Pyinstaller
 &emsp;- This executable was identified as as executable compiled with Pyinstaller

 ### Execution
 &emsp;- Links functions in many DLLs  
 &emsp;- Drops Python (common for packed python executables) along with many cryptologic libraries  
 &emsp;- Drops many more files (common for packed python executables)  
 &emsp;- Communicates with 4 IP addresses and 1 DNS  
 &emsp;- Parses it's PE header  
 &emsp;- Sets Environment Variables  
 &emsp;- Enumerates Files  
  
 ### Interesting Mutex Created    
 &emsp;- Local\SM0:2580:304:WilStaging_02  
 &emsp;&emsp;- This mutex name has been used by the **Yanluowang Ransomware Group** in the past.  
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/mutex.png?raw=true)  
<sub>https://github.com/albertzsigovits/malware-mutex</sub>

__________________________________________________________________________________________________________

 ## Static Analysis & Dynamic Analysis 
 _________________________________________________________________________________________________________  

 **Tool Used:** ProcessMonitor, API Checker, x64dbg, Python  
 **Environment:** Windows 10 VM  
 
 **1. Extract the python code from the pyinstaller archive.**
 Because this executable is compiled with pyinstaller I'm able to pull the original python code out of the executable.  Using uncompyle6 version 3.9.2 I was able to extract the python code titled 
 "code_obf-Statement002.pyc" and many other bundled files from the pyinstaller archive.
<br/>
<br/>  

 **2. First Look At The Code**
 ![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/raw_code.png?raw=true) 
  The code was obfuscated with random variable names and hex strings in place of strings. 
  But I can clearly see the Crypto imports and that variables contain values used in encryption and that they are decrypting the longest string of hex values that contains 33 million characters then executing the string with exec(). 
  The script is only 15 lines so this was very easy to reverse. 
<br/>
<br/>  

**3. Reversed Code And Decrypting The String**
 ![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/reversed_dropper.png?raw=true)  
  I renamed all the variables to match their function and instead of calling the exec function, I write the decrypted data to a file.  
  When trying to run the script it produced this error: SyntaxError: Non-UTF-8 code starting with '\xff' in file. I found that the file was using UTF-16 LE BOM encoding.  I changed it to UTF-8 and the script ran as expected.
 <br/>
 <br/>
 
**3. Discovery Of The Obfuscator**
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/hyperion_obfuscator.png?raw=true)  
 I opened the file that was produced by the decrypt call in Notepad++ and its an obfuscator, specifically the Hyperion Obfuscator, which can be found on Github here https://github.com/billythegoat356/Hyperion. 
 This version is modified and is 7 thousand lines.  I searched for suspicious strings, and got a hit on "lambda".  This revealed a surprise I hadn't caught yet.
 There was code hidden just out of frame in my window padded by white space characters before it. I looked at the right-left scroll bar at the bottom of the file and I can see that I can scroll for a long time to the right.
 This revealed huge strings of hex characters and lambda functions. Below is a snippet, notice how small the scrollbar at the bottom is.
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/hidden_hex_white_space.png?raw=true)  
<br/>
<br/>

**4. Analyzing The Hex**  
 Converting the hex to ascii was yielding nothing useful, I looked closer at the hex and found the magic header for zlib compressed data, "x\9xc".
 With that knowledge I wrote a simple script to decompress it.  I pasted in a snippet of the hex and ran my decompressor.  At first I got an error that its missing the adler32 checksum at the end of the hex so I edited the script to ignore that and write the output to a file.
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/decompressed_partial_hex.png?raw=true)  
 Notice the little message underlined in red that the hacker left us, HA!  "Roses are red, Violets are blue, You are a skid, Nobody likes you".  
 
 
 I wrote a script to defeat the whitespace obfuscation ([Whitespace Deobfuscator](https://github.com/EvanJ4536/Whitespace-Deobfuscator/tree/main)) and extract all the hex strings from the obfuscated code.
 I combined the strings and it resulted in a 15,100,115 character hex string.  I tried to run it through my decompressor
 like I did earlier but I kept getting errors.  Through very long trial and error I was able to pinpoint the error and truncate the compressed data to 5,881,693 and now it decompresses.
 Ill have to investigate later if those extra bytes are part of anything.  For now I think this file is complete the only thing that was added since the last picture was more data appended to the long hex string on line 30.
 I'm pretty sure the huge hex string is again a python script.  Besides that, this script is heavily obfuscated and its going to take some more considerable time and effort to deobfuscate.  But I did find these backwards strings containing imports or function calls.
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/obf_unhexlify.png?raw=true)  
 This gave me the idea to try to unhexify the new hex string.  This revealed encoded data that I was able to identify as base64. I used a base64 decode script to decode it and this produced a python file.
<br/>
<br/>

**5. Investigating The New Python Script**  
 This new script is interesting because it has a few interesting imports like subprocess, urllib, and PIL.  below the imports I can see the PNG file header in a byte string saved to an img_bytes variable.
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/imports_and_image_data.png?raw=true)  
 I copied those bytes into a PIL image viewer script and a partial image of a Bank of America bank statement or something popped up.  Interesting, where's the rest of the image data.
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/BofA_cropped.png?raw=true)  
After hours of combing through the data in this script I can't make any sense of it, coming back to this later.
<br/>
<br/>
 
**6. Going Back To The Other Bundled Files From The Pyinstaller Archive**  
  At this point I wanted to focus on another interesting file I found bundled in the exe called "pyimod01_archive.pyc".  I decompiled it the same way I did the dropper.
  This revealed a decrypter and a custom decompressor written in python.  The decrypter seems to be using tinyaes for encryption and a key imported from a file called "pyimod00_crypto_key" but I can't find it anywhere, could be contained in the compressed data found above or could be 
  generated dynamically.  Dynamic analysis may be my best route here. The decompressor utilizes the decrypter mentioned above to decrypt and then unpack python files back into executable code.  I see a variable in the decompressor referencing the string 
  b'PYZ\x00'.  Amongst the bundled files is a Python Zip Application File named "PYZ-00.pyz".  Traditional attempts to decompress the archive were unsuccessful so the custom decompressor script is for this archive.  I need to find the file "pyimod00_crypto_key".
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/pyimod01_crypter_compressor.png?raw=true)
<br/>
<br/>

**7. Starting Dynamic Analysis**
  Not making considerable progress with static analysis I moved the malware onto a Windows 10 VM with the System Internals Suite.
  Using ProcessMonitor I didn't set any filters so I could capture everything.  I executed the malware and let it run for about 5 minutes.  After it ran for about a minute the same picture I had partially found earlier popped up but it was the full image.  It was just some bogus bank statement picture used in the initial attack to trick the victim.  
  After I stopped seeing ProcMon activity from the original file I stopped the capture and filtered for only events from the original file.  This came up with 865,768 events.  As expected its a huge number  
  because of the fact that pyinstaller compiled code must be unpacked upon execution including all dependencies.  So by default there is a lot of ReadFile, WriteFile, CreateFileMapping events.  Those actions would usually be suspicious.  
<br/>
<br/>

**8. 1st Process**  
  The malware closes and relaunches itself a few times, probably as it goes through its different stages.  I'm thinking every time it decrypts/decompresses parts of itself the new program is launched.  So I'm going to break the analysis up into the different processes.  
  When the malware is launched it quickly checks the BAM logs for its own path to see if this is the first time its been executed and then seemingly crashes and relaunches.  BAM keeps a record of executables launched by each user and can be checked here: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}.  
  By exiting before it actually does anything could be an anti analysis trick to break out of debuggers.
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/stage_1.png?raw=true)
<br/>
<br/>

**9. 2nd Process**
  After the second launch the malware starts inspecting the host system and unpacking itself.  It attempts to open 99 registry keys and queries 38 keys checking things like preferred language, internet cache, AuthenticodeEnabled, LoadAppInit_DLLs, and SafeBoot options but it doesn't modify any keys.  
  When its done checking keys it starts to unpack all its dependencies with ProcMon logging 22,788 ReadFile and WriteFile operations.  You can see it unpacking all its encryption libraries along with numpy, matplotlib and tk.
  It then starts checking registry keys again, a lot of it the same things it checked last time like the BAM registry, SafeBoot and internet cache.  While its doing that it launches another instance of itself then halts activity but doesn't exit.
<br/>
<br/>

**10. 3rd Process**
  During this third process the malware enumerates installed crypto providers and identifies Microsoft Enhanced Cryptographic Provider then loads rsaenh.dll and bcrypt.dll, checks private key policies, and checks fips policies.  
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/get_crypto_provider.png?raw=true)
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/priv_key_settings.png?raw=true)
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/fips_policies.png?raw=true)  
  Over 80 Dlls were loaded in this stage and its notable to say that it searched for CRYPTBASE.dll, NETAPI32.dll, and USERENV.dll is odd places like the desktop, and temp folders failing each time then resorting to the system copy.  
  The IPHLPAPI.dll is also loaded and the malware takes a deep dive into the HKLM\System\CurrentControlSet\Services\WinSock2\Parameters\ registry keys querying the value of atleast 100 of them. I didn't find any evidence of network communications it in my analysis so far.
  Soon after that, it starts reading data from itself in chunks of 8192 bytes and accessing different libraries like tc/tcl, select, and an archive base_library.zip.  As I was going through it I noticed after some read blocks there was a WriteFile operation and it would overwrite an entire file with about the same amount of data that was already in it.
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/pyexpat_overwrite.png?raw=true)
<br/>
<br/>
