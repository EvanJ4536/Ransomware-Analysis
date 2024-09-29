# Ransomware Analysis

## Introduction
This report analyzes Statement009840913.scr, an apparent ransomware variant identified during a recent security incident at my office.  This report aims to outline its behavior, encryption mechanisms, and mitigation strategies.  

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

 ## Behavioral Analysis  

 **Execution**: Upon execution, Statement009840913.scr  
 &emsp;-links functions in many DLLs  
 &emsp;-Installs Python along with many cryptologic libraries  
 &emsp;-Drops many more files  
 &emsp;-Communicates with 4 IP addresses and 1 DNS  
 &emsp;-Parses it's PE header  

 **File Encryption**: Utilizes Python 3.8 to encrypt data with multiple encryption algorithms.

 ## Communications
 Uses SSL to encrypt its communications

 ## Interesting Files  
