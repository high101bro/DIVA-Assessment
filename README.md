# DIVA-Assessment
DIVA (Damn Insecure and Vulnerable Application) Assessment 

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/a6d47a52-ac5b-4697-91b3-c6c15ae5266b)

**DIVA (Damn Insecure and Vulnerable Application)** for Android is an intentionally insecure mobile application designed for the educational purpose of teaching Android application security. The app contains various vulnerabilities that are commonly found in Android applications, making it a useful tool for security professionals, developers, and students to practice their skills in a controlled environment.

DIVA allows users to learn about and test a range of security issues such as SQL injection, insecure data storage, insecure logging, vulnerabilities within the Android platform itself, and problems arising from misconfigured app components. Each section of the app is designed to demonstrate a specific vulnerability, allowing users to exploit it in order to understand how it works and why it is a risk.

By practicing with DIVA, individuals can improve their ability to identify security weaknesses in Android applications, learn how to exploit these vulnerabilities, and gain experience in applying appropriate security measures to protect mobile applications.

The source code for DIVA Android can be found [here](https://github.com/payatu/diva-android) on GitHub by payatu. The original compiled DIVA apk can be found [here](https://github.com/0xArab/diva-apk-file) on Github by 0xArab, but for completeness, I've I've included a copy in this repo.

Here I'll be detailing my process as I assess all thirteen (13) vulnerabilities availabe within DIVA.
0. Environment Configuration and Setup
1. Insecure Loggin
2. Hardcoding Issues - Part 1
3. Insecure Data Storage - Part 1
4. Inseucre Data Storage - Part 2
5. Insecure Data Storage - Part 3
6. Insecure Data Storage Part 4
7. Input Validation Issues - Part 1
8. Input Validation Issues - Part 2
9. Access Control Issues - Part 1
10. Access Control Issues - Part 2
11. Access Control Issues - Part 3
12. Hardcoding Issues - Part 2
13. Input Validation Issues - Part 3

My environment consists of a laptop running Windows 11, with Kali running with WSL - I'm using Win-Kex to view Kali's desktop. [Android Studio](https://developer.android.com/studio?gad_source=1&gclid=CjwKCAjw9IayBhBJEiwAVuc3fqQoq4Q52otj5C432gWKB5goRUia9s-Jcw5vJs5J_g7d68-yjKlklBoCUZQQAvD_BwE&gclsrc=aw.ds) was installed within Kali, rather than within the host Windows environment. A Pixel 3a XL API 25 2 emulator was downloaded and configured within Android Studio and the DIVA apk was installed by being pushed to it via adb (Android Debug Bridge).
