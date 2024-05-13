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

The guide I initially used for training can be found [here](https://can-ozkan.medium.com/damn-insecure-vulnerable-application-diva-apk-walkthrough-66ce37ae8b50) by Can Özkan. They provided a great walkthrough, to which I expanded upon below.

---
---
## Environment Configuration and Setup
[Back to Table of Contents](#table-of-contents)

My environment consists of a laptop running Windows 11, with Kali running with WSL - I'm using Win-Kex to view Kali's desktop. [Android Studio](https://developer.android.com/studio?gad_source=1&gclid=CjwKCAjw9IayBhBJEiwAVuc3fqQoq4Q52otj5C432gWKB5goRUia9s-Jcw5vJs5J_g7d68-yjKlklBoCUZQQAvD_BwE&gclsrc=aw.ds) was installed within Kali, rather than within the host Windows environment. A Pixel 3a XL API 25 2 emulator was downloaded and configured within Android Studio and the DIVA apk was installed by being pushed to it via adb (Android Debug Bridge).

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/ff80bcd1-0449-4a88-b17f-79e63175f675)
![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/665477b7-8f83-4d19-b336-ac2fc03df27d)
![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/e618f7dc-c547-4c15-81d6-ba5f434495fc)

---
---
## Insecure Logging
[Back to Table of Contents](#table-of-contents)

**Insecure logging** refers to the practice of storing sensitive or confidential information in log files without adequate protection. Insecure logging can lead to serious security risks if these log files are accessed by unauthorized users, potentially exposing sensitive data and compromising user privacy. It's essential for developers to implement proper logging mechanisms, including encryption and access controls, to ensure the security of log files and prevent unauthorized access to sensitive information.

Common examples include:
- Logging sensitive data: Developers may inadvertently include sensitive information such as usernames, passwords, API keys, or personally identifiable information (PII) in log messages.
- Logging without encryption: Logging mechanisms may not encrypt the data before writing it to log files, making it vulnerable to interception if accessed by unauthorized parties.
- Failure to restrict access: Log files may be accessible to other applications or users on the device, increasing the risk of unauthorized access to sensitive information.
- Logging in release builds: Developers sometimes forget to disable or remove logging statements in release builds of their applications, potentially exposing sensitive data to users or attackers.

---
### Assessment ###

**Objective**: Find out what is being logged where/how and the vulnerable code.

Within Kali, I decompileed the APK with jadx-gui.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/cfb2f8d0-35e1-457c-a790-c49dbb34b482)

The jadx-gui appears, and I selected the DivaApplication.apk file. Navigating down through the tree you'll find the vulnerable code associated with "LogActivity".

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/a1d308a8-e808-4dc8-9e56-d002ad7fb770)

The vulnerability in this code lies in the insecure logging of credit card information. Specifically, in the `catch` block, the credit card information entered by the user (`cctxt.getText().toString()`) is directly logged to the Android system log using:
```java
Log.e("diva-log", "Error while processing transaction with credit card: " + cctxt.getText().toString())`
```

This poses a significant security risk because sensitive information, such as credit card details, should never be logged in plaintext due to the potential for unauthorized access. If an attacker gains access to the device or the log files, they could easily retrieve the credit card information and misuse it.

To address this vulnerability, developers should avoid logging sensitive information, especially in plaintext. Instead, they should implement secure logging practices such as:

- Logging only necessary information for debugging purposes.
- Ensuring that sensitive data is properly obfuscated or encrypted before being logged.
- Using logging frameworks that support secure logging features, such as log redaction or masking of sensitive information.

By following these practices, developers can prevent the exposure of sensitive information and enhance the security of their applications.

---
### Proof of Concept ###

For a bit of "realism" I looked up 100% fake credit card numbers to test with from [BlueSnap Developers]... doesn't matter though.

I navigated to "1. Insecure Logging" and entered the fake credit card number.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/fa68a2a6-0aac-45af-9a15-bca27ba57fa6)

Using **adb logcat**, you can view the Android system logs.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/c1809cf9-fdb8-487b-9a9a-1caa07bda114)

Note that you see the fake credit card information logged!

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/26a6b078-2eb4-48a1-bca9-c1e04ad3d5fb)

---
---
## Hardcoding Issues - Part 1
[Back to Table of Contents](#table-of-contents)

**Hardcoding Issues** in Android applications refer to the practice of embedding sensitive information directly into the source code or resources of the application. This presents a significant security risk because anyone with access to the application's code can easily extract these hardcoded values, potentially leading to unauthorized access or misuse of sensitive data.

Common examples of hardcoded issues in applications include:
- API Keys: Embedding API keys directly into the source code makes them vulnerable to extraction by decompiling the application, exposing them to potential misuse or abuse.
- Passwords and Credentials: Storing passwords or other sensitive credentials directly in the code or resources can lead to security breaches if the application is compromised.
- URLs and Endpoints: Hardcoding URLs or endpoints for API calls without proper encryption or obfuscation can expose the backend infrastructure to potential attacks, such as man-in-the-middle (MITM) attacks or unauthorized access.

---
### Assessment ###

**Objective**: Find out what is hardcoded and where.

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "HardcodeActivity".

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/2a1ee036-7c94-4619-9bb4-d5cc09955b68)

The vulnerability in this code lies in the hardcoding of the secret key directly within the application code. Specifically, the secret key "vendorsecretkey" is hardcoded in the `if` statement:

```java
if (hckey.getText().toString().equals("vendorsecretkey")) {
```

This means that anyone who decompiles the application or inspects the source code can easily identify the secret key. Consequently, an attacker could extract the key and gain unauthorized access to the application's sensitive functionality or data.

To address this vulnerability, developers should avoid hardcoding sensitive information like secret keys directly into the application code. Instead, they should use secure storage mechanisms or external configuration files to store such sensitive data, thereby reducing the risk of exposure to potential attackers.

---
### Proof of Concept ###

From the above code assessment, you'll see that the hardcoded password is "vendorsecretkey".

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/ac25ea53-f8f8-4b74-a8b9-93a1f1fb8e8c)


---
---
## Insecure Data Storage - Part 1
[Back to Table of Contents](#table-of-contents)

Insecure data storage refers to the practice of storing sensitive information in an unprotected or vulnerable manner, making it susceptible to unauthorized access or disclosure. In the context of Android applications, insecure data storage vulnerabilities typically involve storing sensitive data such as passwords, API keys, personal information, or financial data in plaintext or in inadequately secured storage locations.

Common examples of insecure data storage vulnerabilities in Android applications include:
- **Shared Preferences**: Storing sensitive information using the SharedPreferences API without proper encryption or access controls can expose the data to other applications or unauthorized users.
- **SQLite Databases**: Storing sensitive data in SQLite databases without encryption or proper access controls can lead to unauthorized access if the device is compromised.
- **External Storage**: Storing sensitive data on external storage such as the SD card without encryption can expose the data to other apps or users with physical access to the device.
- **Logs**: Logging sensitive information such as passwords or credit card numbers without proper encryption or redaction can expose the data to unauthorized users if the log files are accessed.
- **Caching Mechanisms**: Storing sensitive data in caches without proper encryption or access controls can expose the data to other apps or users with access to the device.

By addressing insecure data storage vulnerabilities, developers can protect sensitive user data from unauthorized access and enhance the overall security of their Android applications.

---
### Assessment ###

**Objective**: Find out where/how the credentials are being stored and the vulnerable code.

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "InsecureDataStorage1Activity".

The vulnerability in the code lies in the insecure storage of sensitive information, specifically the username and password, using SharedPreferences without encryption. Here's where the vulnerability resides within the code:

```java
// Storing Data in SharedPreferences
spedit.putString("user", usr.getText().toString());
spedit.putString("password", pwd.getText().toString());
```

These lines of code store the username and password entered by the user directly into the SharedPreferences without any form of encryption or protection. As a result, the sensitive information (password in particular) is stored in plaintext, making it vulnerable to unauthorized access if the device or SharedPreferences file is compromised.

SharedPreferences is not designed to securely store sensitive data such as passwords. While SharedPreferences provides a simple key-value storage mechanism, the data stored in SharedPreferences is not encrypted and can be easily accessed by other apps or users with root access to the device.

As a result, if an attacker gains access to the device or the SharedPreferences file, they can easily retrieve the stored credentials and misuse them for unauthorized access or other malicious purposes.

To address this vulnerability, developers should:
- Use more secure storage mechanisms for sensitive data, such as the Android Keystore system for encryption keys or encrypted databases like SQLCipher for storing passwords and other sensitive information.
- Avoid storing sensitive data like passwords in plaintext and always encrypt sensitive data before storing it on the device.
- Implement proper access controls and encryption techniques to protect sensitive data from unauthorized access.
- This one is a bit out of scope, but educate users about the importance of secure password management practices and encourage them to use strong, unique passwords for their accounts.

---
### Proof of Concept ###

First I input my credentials into the app.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/87980328-883d-47ec-9682-c878b1b2a59c)

From the code assessment above, we can **adb shell** and navigate to where the diva.apk stores the insecure file and view the stored credentials. First we list the package with `pm list packages | grep diva`, then use that to navigate to where the apk stores files at `/data/data/jakhar.aseem.diva/shared_prefs/`. You'll identify that my password was stored as plaintext in `jakhar.aseem.diva_preferences.xml` as **My_Super_Insecure_Password!!!**.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/3d987172-7196-4d6e-b28f-e3a090a32ba0)


---
---
## Insecure Data Storage - Part 2
[Back to Table of Contents](#table-of-contents)

Reference [Insecure Data Storage - Part 1](#insecure-data-storage---part-1) for a description about this vulnerability.

---
### Assessment ###

**Objective**: Find out where/how the credentials are being stored and the vulnerable code.

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "InsecureDataStorage2Activity".

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/dc129d15-bf55-46a4-a3f0-1aba61692cca)

This time, the credentials are stored within an sqlite3 local database.

The vulnerability in this code lies in the insecure storage of credentials in an SQLite database without proper parameterization or encryption. Here's where the insecurity is highlighted within the code:

```java
public void saveCredentials(View view) {
    EditText usr = (EditText) findViewById(R.id.ids2Usr);
    EditText pwd = (EditText) findViewById(R.id.ids2Pwd);
    try {
        // Insecure SQL query concatenation
        this.mDB.execSQL("INSERT INTO myuser VALUES ('" + usr.getText().toString() + "', '" + pwd.getText().toString() + "');");
        this.mDB.close();
    } catch (Exception e) {
        Log.d("Diva", "Error occurred while inserting into database: " + e.getMessage());
    }
    Toast.makeText(this, "3rd party credentials saved successfully!", 0).show();
}
```

The vulnerability lies in the insecure SQL query concatenation used to insert user credentials into the SQLite database. User inputs (`usr.getText().toString()` and `pwd.getText().toString()`) are directly concatenated into the SQL query string, making the application vulnerable to SQL injection attacks. An attacker could manipulate the input fields to execute arbitrary SQL commands, leading to unauthorized data manipulation or extraction.

To address this vulnerability, developers should use parameterized queries or prepared statements to safely insert user inputs into SQL queries. Additionally, sensitive data such as passwords should be stored securely, preferably using encryption techniques, to protect against unauthorized access even if the database is compromised.

---
### Proof of Concept ###

First I input my credentials into the app.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/acd99889-91bf-436d-9de4-5abfd02f74cd)

Using **adb shell**, navigate to where the diva databases are located. There you can cat the file and see the insecure credentials within this string `*!Ghigh101broMy_Super_Insecure_Password!!!` - though a bit messy.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/758d1dbe-945c-40e6-ab8b-bab2b90b97ed)

Using sqlite3 commands, you can mount the database, numerate the tables, and view the contents which reveals that the credentials are stored in plaintext.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/ab54fb14-62f5-4066-b299-1d4b4bb72276)


---
---
## Insecure Data Storage - Part 3
[Back to Table of Contents](#table-of-contents)

---
### Assessment ###

**Objective**: 

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "".

---
### Proof of Concept ###



---
---
## Insecure Data Storage Part 4
[Back to Table of Contents](#table-of-contents)

---
### Assessment ###

**Objective**: 

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "".

---
### Proof of Concept ###



---
---
## Input Validation Issues - Part 1
[Back to Table of Contents](#table-of-contents)

---
### Assessment ###

**Objective**: 

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "".

---
### Proof of Concept ###



---
---
## Input Validation Issues - Part 2
[Back to Table of Contents](#table-of-contents)

---
### Assessment ###

**Objective**: 

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "".

---
### Proof of Concept ###



---
---
## Access Control Issues - Part 1
[Back to Table of Contents](#table-of-contents)

---
### Assessment ###

**Objective**: 

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "".

---
### Proof of Concept ###



---
---
## Access Control Issues - Part 2
[Back to Table of Contents](#table-of-contents)

---
### Assessment ###

**Objective**: 

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "".

---
### Proof of Concept ###



---
---
## Access Control Issues - Part 3
[Back to Table of Contents](#table-of-contents)

---
### Assessment ###

**Objective**: 

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "".

---
### Proof of Concept ###



---
---
## Hardcoding Issues - Part 2
[Back to Table of Contents](#table-of-contents)

---
### Assessment ###

**Objective**: 

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "".

---
### Proof of Concept ###



---
---
## Input Validation Issues - Part 3
[Back to Table of Contents](#table-of-contents)

---
### Assessment ###

**Objective**: 

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "".

---
### Proof of Concept ###



