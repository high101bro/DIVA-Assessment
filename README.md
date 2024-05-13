# DIVA-Assessment
DIVA (Damn Insecure and Vulnerable Application) Assessment 

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/a6d47a52-ac5b-4697-91b3-c6c15ae5266b)

**DIVA (Damn Insecure and Vulnerable Application)** for Android is an intentionally insecure mobile application designed for the educational purpose of teaching Android application security. The app contains various vulnerabilities that are commonly found in Android applications, making it a useful tool for security professionals, developers, and students to practice their skills in a controlled environment.

DIVA allows users to learn about and test a range of security issues such as SQL injection, insecure data storage, insecure logging, vulnerabilities within the Android platform itself, and problems arising from misconfigured app components. Each section of the app is designed to demonstrate a specific vulnerability, allowing users to exploit it in order to understand how it works and why it is a risk.

By practicing with DIVA, individuals can improve their ability to identify security weaknesses in Android applications, learn how to exploit these vulnerabilities, and gain experience in applying appropriate security measures to protect mobile applications.

The source code for DIVA Android can be found [here](https://github.com/payatu/diva-android) on GitHub by payatu. The original compiled DIVA apk can be found [here](https://github.com/0xArab/diva-apk-file) on Github by 0xArab, but for completeness, I've I've included a copy in this repo.

Here I'll be detailing my process as I assess all thirteen (13) vulnerabilities availabe within DIVA.
## Table of Contents
- [Environment Configuration and Setup](#environment-configuration-and-setup)
1. [Insecure Logging](#insecure-logging)
2. [Hardcoding Issues - Part 1](#hardcoding-issues---part-1)
3. [Insecure Data Storage - Part 1](#insecure-data-storage---part-1)
4. [Insecure Data Storage - Part 2](#insecure-data-storage---part-2)
5. [Insecure Data Storage - Part 3](#insecure-data-storage---part-3)
6. [Insecure Data Storage Part 4](#insecure-data-storage-part-4)
7. [Input Validation Issues - Part 1](#input-validation-issues---part-1)
8. [Input Validation Issues - Part 2](#input-validation-issues---part-2)
9. [Access Control Issues - Part 1](#access-control-issues---part-1)
10. [Access Control Issues - Part 2](#access-control-issues---part-2)
11. [Access Control Issues - Part 3](#access-control-issues---part-3)
12. [Hardcoding Issues - Part 2](#hardcoding-issues---part-2)
13. [Input Validation Issues - Part 3](#input-validation-issues---part-3)


## Environment Configuration and Setup
[Back to Table of Contents](#table-of-contents)

My environment consists of a laptop running Windows 11, with Kali running with WSL - I'm using Win-Kex to view Kali's desktop. [Android Studio](https://developer.android.com/studio?gad_source=1&gclid=CjwKCAjw9IayBhBJEiwAVuc3fqQoq4Q52otj5C432gWKB5goRUia9s-Jcw5vJs5J_g7d68-yjKlklBoCUZQQAvD_BwE&gclsrc=aw.ds) was installed within Kali, rather than within the host Windows environment. A Pixel 3a XL API 25 2 emulator was downloaded and configured within Android Studio and the DIVA apk was installed by being pushed to it via adb (Android Debug Bridge).

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/ff80bcd1-0449-4a88-b17f-79e63175f675)
![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/665477b7-8f83-4d19-b336-ac2fc03df27d)
![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/e618f7dc-c547-4c15-81d6-ba5f434495fc)


## Insecure Logging
[Back to Table of Contents](#table-of-contents)

Insecure logging refers to the practice of storing sensitive or confidential information in log files without adequate protection. This could include usernames, passwords, API keys, or other personally identifiable information (PII). Insecure logging can lead to serious security risks if these log files are accessed by unauthorized users, potentially exposing sensitive data and compromising user privacy. It's essential for developers to implement proper logging mechanisms, including encryption and access controls, to ensure the security of log files and prevent unauthorized access to sensitive information.

Insecure logging can pose significant security risks, as it may lead to data breaches, privacy violations, and regulatory compliance issues. To mitigate these risks, developers should follow best practices for secure logging, including:
- Avoiding logging sensitive information unless absolutely necessary.
- Encrypting sensitive data before writing it to log files.
- Implementing access controls to restrict access to log files.
- Using conditional logging to ensure that sensitive information is not logged in release builds.
- Regularly reviewing and auditing log files for security vulnerabilities.

By addressing these concerns, developers can help protect user data and maintain the security of their Android applications.

---

Within Kali, I decompileed the APK with jadx-gui.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/cfb2f8d0-35e1-457c-a790-c49dbb34b482)

The jadx-gui appears, and I selected the DivaApplication.apk file. Navigating down through the tree you'll find the code associated with "LogActivity".

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/a1d308a8-e808-4dc8-9e56-d002ad7fb770)

###Assessment###
The insecure aspect of the code lies in the logging mechanism used within the catch block. Specifically, it logs the credit card information directly to the log file using **Log.e("diva-log", "Error while processing transaction with credit card: " + cctxt.getText().toString())**. This means that if an error occurs during the transaction process, the credit card information entered by the user will be logged without any encryption or obfuscation. This poses a significant security risk as it exposes sensitive credit card data to potential attackers who may gain unauthorized access to the log files.

###Proof of Concept###

For "realism" I looked up 100% fake credit card numbers to test with from [BlueSnap Developers]

I navigated to "1. Insecure Logging" and entered the fake credit card number.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/fa68a2a6-0aac-45af-9a15-bca27ba57fa6)

Using **adb logcat**, you can view the Android logs.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/c1809cf9-fdb8-487b-9a9a-1caa07bda114)

Note that you see the fake credit card information logged!

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/26a6b078-2eb4-48a1-bca9-c1e04ad3d5fb)



## Hardcoding Issues - Part 1
[Back to Table of Contents](#table-of-contents)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/182f37be-fe48-4f01-9794-39b1d9590e74)


## Insecure Data Storage - Part 1
[Back to Table of Contents](#table-of-contents)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/665088df-be89-436e-a6f6-ba01c1dca27b)


## Insecure Data Storage - Part 2
[Back to Table of Contents](#table-of-contents)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/441b3a0d-1e81-4a40-8272-833f378fc8f9)


## Insecure Data Storage - Part 3
[Back to Table of Contents](#table-of-contents)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/609f9220-bd84-4847-a16c-92dfc8867b6e)


## Insecure Data Storage Part 4
[Back to Table of Contents](#table-of-contents)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/b93ccd74-df1a-4a51-9156-d94cf7eda838)


## Input Validation Issues - Part 1
[Back to Table of Contents](#table-of-contents)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/6a90ec27-9dab-4c53-8b5a-cbc79cf42bef)


## Input Validation Issues - Part 2
[Back to Table of Contents](#table-of-contents)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/97441cd3-5245-4309-a71d-fa3c70c851ab)


## Access Control Issues - Part 1
[Back to Table of Contents](#table-of-contents)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/ed407483-a371-4fcd-ae2b-7dbc6d5dbc97)


## Access Control Issues - Part 2
[Back to Table of Contents](#table-of-contents)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/b1d89686-aa9f-468e-8422-eae1a692143f)


## Access Control Issues - Part 3
[Back to Table of Contents](#table-of-contents)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/f6a9357d-daa1-4b44-b640-e57f502abfa4)


## Hardcoding Issues - Part 2
[Back to Table of Contents](#table-of-contents)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/1833520b-cd56-4c0c-a73f-4e3672dc0884)


## Input Validation Issues - Part 3
[Back to Table of Contents](#table-of-contents)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/767233a8-e24e-4627-a8eb-83091cb3986f)



