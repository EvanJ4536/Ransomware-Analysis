# Ransomware Analysis: Statement009840913.scr

## Introduction
This report analyzes Statement009840913.scr, a new ransomware variant identified during a recent security incident at my office.  This report aims to outline its behavior, encryption mechanisms, and mitigation strategies.  

## Overview
| Basic Information |  |
| ----------------- | ---------------- |
| **Name** | Statement009840913.scr |
| **Family** | Yanluowang |
| **Date Detected** | 9/14/2024 |
| **SHA-256** | df44a4e931a572d24413fa0611001b57d595a984b14220f2996e83b582a2d901 |
| **File Type**  | Portable Executable  |
| **Size**  | 51,327,578 bytes  |

 The executable seems to be packed by Pyinstaller.  

 ## Infection Vector

 This ransomware was received in a Phishing email sent to our support department.  The attacker claimed to be a customer that was over charged. They sent an email with an attachment of a "Screenshot of their bank statment" in the form of an Executable Screensaver format.  The attachment had the icon of a pdf file and requested administrator access when executed.  

 ## Behavioral Analysis  

 **Execution**: Upon execution, Statement009840913.scr  
 &emsp;-links functions in many DLLs  
 &emsp;-Installs Python along with many cryptologic libraries  
 &emsp;-Drops many more files  
 &emsp;-Communicates with 4 IP addresses and 1 DNS  
 &emsp;-Parses it's PE header  

 **File Encryption**: Utilizes Python 3.8 and multiple encryption alogrithms  
 &emsp;-**Algorithms**  
 &emsp;-**Key Generation**  

 ## Interesting Files  
