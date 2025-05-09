# Ransomware Analysis

## Introduction
This report analyzes a file: Statement009840913.scr, an apparent ransomware variant identified during a recent security incident at my office.  This report aims to outline my findings in static and behavioral analysis.  

Here is a Threat Graph I made on virus total: https://www.virustotal.com/graph/g85c720a1b4c546b3bf0d8170333b2b99a7c42e844c5c47c5af8b6d614bbe8c2e  

## Overview
| Basic Information |  |
| ----------------- | ---------------- |
| **Name** | Statement009840913.scr |
| **Family** | Yanluowang |
| **Date Detected** | 9/14/2024 |
| **SHA-256** | df44a4e931a572d24413fa0611001b57d595a984b14220f2996e83b582a2d901 |
| **File Type**  | Portable Executable  |
| **Size**  | 51,327,578 bytes  |

 At the date of detection, this file had never been uploaded to virustotal, and was detected by 4 out of 72 antivirus. 

 ## Infection Vector

 This ransomware was received in a Phishing email sent to our support department.  The attacker claimed to be a customer that was over charged. They sent an email with an attachment of a "Screenshot of their bank statment" in the form of an Executable Screensaver format.  The attachment had the icon of a pdf file and requested administrator access when executed.  

__________________________________________________________________________________________________________  

 ## Behavioral Analysis   

 ### Execution
 &emsp;- links functions in many DLLs  
 &emsp;- Installs Python along with many cryptologic libraries  
 &emsp;- Drops many more files  
 &emsp;- Communicates with 4 IP addresses and 1 DNS  
 &emsp;- Parses it's PE header  
 &emsp;- Sets Environment Variables  
 &emsp;- Enumerates Files  
 
 **File Encryption**: Utilizes Python 3.8 to encrypt data.
 
 ### Interesting Mutex Created    
 &emsp;- Local\SM0:2580:304:WilStaging_02  
 &emsp;&emsp;- This mutex name has been used by the **Yanluowang Ransomware Group** in the past.  
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/mutex.png?raw=true)
<sub>https://github.com/albertzsigovits/malware-mutex</sub>

__________________________________________________________________________________________________________

 ## Static Analysis  
 _________________________________________________________________________________________________________
 **1. Extract the python code from the pyinstaller archive.**
 Using uncompyle6 version 3.9.2 I was able to extract the python code titled 
 "code_obf-Statement002.pyc" and many other bundled files from the pyinstaller archive.
<br/>
<br/>  
 **2. First look at the code**
 ![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/raw_code.png?raw=true)  
  The code was obfuscated with random variable names and hex strings in place of strings. 
  But I can clearly see the Crypto imports and that variables contain values used in encryption and that they are decrypting the longest string of hex values that contains 33 million characters then executing the string with exec(). 
  The script is only 15 lines so this was very easy to reverse. 
<br/>
<br/>  
**3. Reversed code and decrypting the string**
 ![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/reversed_dropper.png?raw=true)  
  I renamed all the variables to match their function and instead of calling the exec function I write the decrypted data to a file.  
  When trying to run the script it produced this error: SyntaxError: Non-UTF-8 code starting with '\xff' in file. I found that the file was using UTF-16 LE BOM encoding.  I changed it to UTF-8 and the script ran as expected.
 <br/>
 <br/>
 
**3. Discovery of obfuscator**
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/hyperion_obfuscator.png?raw=true)  
 I opened the file that was produced by the decrypt call in Notepad++ and its an obfuscator, specifically the Hyperion Obfuscator, which can be found on github here https://github.com/billythegoat356/Hyperion. 
 This version is modified and is 7 thousand lines.  Probably just a tactic to make this process more confusing.  I searched for suspicious strings, and got a hit on "lambda".  This revealed a suprise I hadn't caught while looking through the file visually.
 There was code hidden just out of frame in my window padded by white space characters before it. I looked at the right-left scroll bar at the bottom of the file and I can see that I can scroll for a long time to the right.
 This revealed huge strings of hex characters and lambda functions. Below is a snippet, notice how small the scrollbar at the bottom is.
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/hidden_hex_white_space.png?raw=true)  
<br/>
<br/>

**4. Analyzing the hex**
 Converting the ascii to hex was yielding nothing useful, I looked closer at the hex and found the magic header for compressed data, "x\9xc".
 With that knowledge I wrote a simple script to decompress it using zlib.  At first I got an error that its missing the adler32 checksum at the end of the hex so I edited the script to be able to ignore that and decompress whatever I have and wrote the output to a file.
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/decompressed_partial_hex.png?raw=true)  
 Notice the little message underlined in red that the hacker left us!  Besides that, this script is heavily obfuscated and its going to take considerable time and effort to deobfuscate.  
 I might be able to find out more information, easier with dynamic analysis later.
<br/>
<br/>
 
**5. Going back to the other bundled files from the pyinstaller archive**
  At this point I put a pause on going further into the file decompression and focused on another interesting file I found bundled called "pyimod01_archive.pyc".  I decompiled it the same way I did the dropper.
  This revealed a decrypter and a custom decompressor.  The decrypter seems to be using tinyaes for encryption and a key imported from a file called "pyimod_crypto_key" but I can't find it anywhere, could be contained in the compressed data found above or could be generated dynamically.
  Dynamic analysis may be my best route here. The decompressor utilizes the decrypter mentioned above to decrypt and then unpack python files back into executable code.  
  Is it doing this so it can run python scirpts instead of an exe?
![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/pyimod01_crypter_compressor.png?raw=true)
<br/>
<br/>
