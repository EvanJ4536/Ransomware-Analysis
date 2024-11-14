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
 ### Interesting Functions I've Reverse Engineered <sub>(Variable names changed for simplicity)
 _________________________________________________________________________________________________________
 **1. This function deletes an Environment Variable.**
 ![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/remove_env_var.png?raw=true)   
 Takes a series of bytes into the Pointer variable. Pointer is then passed into the Convert_To_Wide_Char function, and this returns a desired Environment_Variable_Name.  Then SetEnvironmentVariableW() is called and our Environment_Variable_Name is passed in as well as a nullptr.  When a null value is supplied for lpValue in SetEnvironmentVariableW(lpName, lpValue), the environment variable named lpName will be deleted from the current process. Therefore the environment variable with the same name as Environment_Variable_Name that we passed in will be removed.  
<br/>
<br/>  
 **2. This function loads a DLL from an altered path into the current process's address space**
 ![alt text](https://github.com/EvanJ4536/Ransomware-Analysis/blob/main/pngs/DLL-side-loading.png?raw=true)  
 Takes a uint8_t as a parameter that holds integer values that represent the ASCII values for an absolute path to a file (this is an obfusication attempt I think), converts it to 16 bit wide char then passes it into LoadLibraryExW() as the library file path with the flag LOAD_WITH_ALTERED_SEARCH_PATH.
<br/>
<br/>  
  
