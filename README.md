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

Using **adb shell**, you can identify where the files are stored, and identified the insecure file containing the credentials:

![Screenshot 2024-05-13 130112](https://github.com/high101bro/DIVA-Assessment/assets/13679268/d314013a-574d-4584-8685-f312cf21cfcd)


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

The vulnerability in this code lies in the insecure storage of credentials in an SQLite database without proper parameterization or encryption. Here's where the insecurity is within the code:

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

Reference [Insecure Data Storage - Part 1](#insecure-data-storage---part-1) for a description about this vulnerability.

---
### Assessment ###

**Objective**: Find out where/how the credentials are being stored and the vulnerable code.

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "InsecureDataStorage3Activity".

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/78da7d70-3e74-4c3b-a271-07260b99e402)

The vulnerability in this code lies in the insecure storage of credentials as plaintext files in the device's internal storage. Here's where the insecurity resides within the code:

```java
File uinfo = File.createTempFile("uinfo", "tmp", ddir);
uinfo.setReadable(true);
uinfo.setWritable(true);
FileWriter fw = new FileWriter(uinfo);
fw.write(usr.getText().toString() + ":" + pwd.getText().toString() + "\n");
fw.close();
```

These lines of code create a temporary file named "uinfo.tmp" in the application's data directory and write the username and password entered by the user directly into this file as plaintext. Additionally, the file permissions are set to readable and writable, making the credentials accessible to other applications or users with access to the device.

Storing sensitive information like usernames and passwords in plaintext files without encryption or proper access controls poses a significant security risk. If an attacker gains access to the device or the file system, they can easily retrieve the plaintext credentials and misuse them for unauthorized access or other malicious purposes.

---
### Proof of Concept ###

First I input my credentials into the app.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/ce730737-4b5e-4520-9a9a-4f3f00a291bb)

As the assessment identified, the credentials are stored within a temporary file that contains both `uinfo` and `tmp` in the filename. Using **abd shell** we can navigate to the diva apk location and look for the inseucre file to file the credentials strored in plaintext.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/7e1dd8fa-11e8-4985-982c-7ad91345dd47)


---
---
## Insecure Data Storage Part 4
[Back to Table of Contents](#table-of-contents)

Reference [Insecure Data Storage - Part 1](#insecure-data-storage---part-1) for a description about this vulnerability.

---
### Assessment ###

**Objective**: Find out where/how the credentials are being stored and the vulnerable code.

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "InsecureDataStorage3Activity".

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/84fd38cb-065b-4e5f-877a-6523731b1df5)

The vulnerability in this code lies in the insecure storage of credentials on external storage without proper encryption or access controls. Here's where the insecurity resides within the code:

```java
// Storing Credentials on External Storage
File sdir = Environment.getExternalStorageDirectory();
try {
    File uinfo = new File(sdir.getAbsolutePath() + "/.uinfo.txt");
    uinfo.setReadable(true);
    uinfo.setWritable(true);
    FileWriter fw = new FileWriter(uinfo);
    fw.write(usr.getText().toString() + ":" + pwd.getText().toString() + "\n");
    fw.close();
    Toast.makeText(this, "3rd party credentials saved successfully!", 0).show();
} catch (Exception e) {
    Toast.makeText(this, "File error occurred", 0).show();
    Log.d("Diva", "File error: " + e.getMessage());
}
```

This code segment creates a file named ".uinfo.txt" on the external storage directory and writes the username and password entered by the user into this file. However, there are several insecurities:
- **No Encryption**: The credentials are stored in plaintext, without any encryption. This makes them easily accessible to anyone with access to the external storage, such as other apps or users with physical access to the device.
- **No Access Controls**: The file permissions are set to readable and writable for all users (`uinfo.setReadable(true);` and `uinfo.setWritable(true);`). This means that any app or user with access to the external storage can read or modify the credentials, increasing the risk of unauthorized access.
- **No Secure Storage**: External storage is not a secure location for storing sensitive information like credentials. It's susceptible to various attacks, such as data leakage, theft, or unauthorized access.

Overall, storing credentials in plaintext on external storage without encryption or access controls poses a significant security risk and should be avoided in favor of more secure storage mechanisms, such as the Android Keystore or encrypted databases.

---
### Proof of Concept ###

First I input my credentials into the app.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/7faf8731-5d04-49b1-8ae5-f10fae94bc84)

As the assessment detailed, the credentials are being stored in an external storage device. Within an **adb shell** of the android device, we can do a brute force search for this file using the `find` command to locate the file and view its contents. 

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/a5038ef9-9e96-4fc3-b6ea-8e41a6ef495e)


---
---
## Input Validation Issues - Part 1
[Back to Table of Contents](#table-of-contents)

Input validation in Android applications involves verifying and sanitizing user inputs to ensure that they meet certain criteria, such as format, length, or range, before processing or using them. Proper input validation is crucial for preventing security vulnerabilities, such as injection attacks, data breaches, and unexpected behavior.

Here are some key aspects of input validation in Android applications:
- **Sanitizing Input**: Sanitize user inputs by removing or escaping any potentially harmful characters or sequences that could be used to exploit vulnerabilities, such as SQL injection, XSS (Cross-Site Scripting), or command injection.
- **Validating Format**: Check that user inputs adhere to the expected format, such as email addresses, phone numbers, dates, or credit card numbers. Regular expressions (`Pattern` class in Java) can be used for pattern matching and validation.
- **Limiting Input Length**: Enforce maximum length limits on text input fields to prevent buffer overflow vulnerabilities or denial-of-service attacks caused by excessively large inputs.
- **Validating Range**: Ensure that numeric inputs fall within acceptable ranges to prevent numeric overflow or underflow, as well as to enforce business logic constraints.
- **Handling Special Characters**: Be cautious with special characters, such as whitespace, newline characters, or control characters, which could lead to unexpected behavior or security vulnerabilities if not properly handled.
- **Using Input Masks**: Implement input masks to guide users in entering data in the correct format (e.g., phone numbers, credit card numbers) and reduce the likelihood of input errors.
- **Client-Side and Server-Side Validation**: Perform input validation both on the client-side (in the Android app) and the server-side (on the backend server) to provide defense-in-depth against attacks and ensure data integrity.
- **Error Handling**: Provide meaningful error messages to users when validation fails, indicating why their input was rejected and how they can correct it. Avoid revealing sensitive information in error messages.
- **Testing and Validation**: Thoroughly test input validation mechanisms to ensure they function correctly under various conditions, including edge cases and malicious inputs. Automated testing tools and manual testing can help identify vulnerabilities and weaknesses.

By implementing robust input validation mechanisms, Android developers can enhance the security and reliability of their applications, reducing the risk of security breaches and ensuring a positive user experience.

---
### Assessment ###

**Objective**: Try to access all user data without knowing any user name. There are three users by default and your task is to output data of all the three users with a single malicious search.

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "SQLInjectionActivity".

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/b290976c-ca17-4b35-abf8-a6d8b18cd928)

Aside from the obvious credentials being in plaintext in the decompiled apk (this is out of scope for this exercise), there is a vulnerability in the provided code, specifically in the `search` method. 

Here's the vulnerable section:

```java
Cursor cr = this.mDB.rawQuery("SELECT * FROM sqliuser WHERE user = '" + srchtxt.getText().toString() + "'", null);
```

In this line, the user input (`srchtxt.getText().toString()`) is directly concatenated into the SQL query string without proper sanitization or parameterization. This makes the application vulnerable to SQL injection attacks.

In SQL injection attacks, attackers can manipulate the input to modify the intended SQL query or execute arbitrary SQL commands. For example, an attacker could input `' OR 1=1 --` as the username, which would cause the SQL query to return all records from the `sqliuser` table, effectively bypassing any authentication logic.

To mitigate this vulnerability, developers should use parameterized queries or prepared statements to handle user input safely. Parameterized queries separate the SQL query from the user input, preventing attackers from injecting malicious SQL code.

Here's an example of how to use parameterized queries in Android SQLite:

```java
Cursor cr = this.mDB.rawQuery("SELECT * FROM sqliuser WHERE user = ?", new String[]{srchtxt.getText().toString()});
```

In this version, the user input is passed as a parameter to the query, and the SQLite database engine handles the parameterization, ensuring that the input is treated as data and not as part of the SQL command. This approach prevents SQL injection vulnerabilities.

Alternatively, you can connect to the `sqlite3` database and with **adb shell** and collect all the credentials as the datase is also insecure. That said, this part is out of scope.

---
### Proof of Concept ###

I input the `` OR 1=1 --' into the application search field and it dumps all the contents of the sqlite3 database, in this case the credentials, to the screen.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/d168447f-3386-4083-a67d-8d7b185c8a60)

Alternatively, you can connect to the `sqlite3` database and with **adb shell** and collect all the credentials as the datase is also insecure. That said, this part is out of scope.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/bd08d219-18a9-4a90-a87c-1b3da193d874)

Oh, another way too is to export the sqlite3 database using `adb pull` to the kali host to run `sqlmap` against it. This is particularly useful if the simple `' OR 1=1 --` does not work and you're looking to use more complex sql injection strings.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/078c6df5-8619-4e55-8d9b-bc2f33a571c5)

A bit out of scope again, but wanted to test with sqlmap regardless.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/53058c29-1ecc-47f3-989e-2f8bf71b55ba)


---
---
## Input Validation Issues - Part 2
[Back to Table of Contents](#table-of-contents)

Reference [Input Validation Issues - Part 1](#input-validation-issues---part-1) for a description about this vulnerability.

---
### Assessment ###

**Objective**: Try accessing any sensitive information apart from a web URL.

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "InputValidation2URISchemeActivity".

Yes, there is a vulnerability in the provided code. 

The vulnerability lies in the `get()` method, specifically in the following line:

```java
wview.loadUrl(uriText.getText().toString());
```

This line loads a URL into a `WebView` directly based on user input (`uriText.getText().toString()`). This can lead to security risks such as open redirect vulnerabilities or the potential for loading malicious content from untrusted sources.

An attacker could exploit this vulnerability by providing a malicious URL as input, potentially leading to attacks such as phishing or cross-site scripting (XSS) if the `WebView` does not properly sanitize or restrict the URLs it loads.

To mitigate this vulnerability, input validation and sanitization should be performed on the user-provided URL before loading it into the `WebView`. Additionally, the app should enforce a strict policy on which URLs can be loaded to prevent open redirects and other security risks.

---
### Proof of Concept ###

Testing access to webpages, and various files within the system. The issue here is that the user can view unauthorized files.

| URL Success | File Success | File Failure |
| ----------- | ------------ | ------------ |
| ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/a6d785df-7deb-4a44-b4f3-e2c48fff1477) | ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/88e55c42-a3e0-47fe-a678-6e4250c1e8a6) | ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/00624099-7227-4438-866f-4e277590f57a) |


---
---
## Access Control Issues - Part 1
[Back to Table of Contents](#table-of-contents)

Access control issues in Android applications refer to vulnerabilities that allow unauthorized users or components to gain access to sensitive functionality or data. These issues typically arise due to improper implementation of access control mechanisms within the app. Here are some common access control issues in Android applications:
- **Improper Authentication**: Apps may lack proper authentication mechanisms, allowing unauthorized users to access restricted features or data.
- **Insufficient Authorization**: Even if authentication is implemented, apps may fail to enforce proper authorization checks, allowing authenticated users to access functionality or data they shouldn't have access to.
- **Insecure Data Transmission**: Apps may transmit sensitive data over unencrypted channels or without proper authentication, allowing attackers to intercept and access the data.
- **Insecure Data Storage**: Apps may store sensitive data insecurely, such as in plaintext or in accessible locations, allowing unauthorized access to the data.
- **Insecure Component Integration**: Apps may integrate with other components, such as content providers or activities, without proper access controls, allowing attackers to exploit these components to gain access to sensitive functionality or data.
- **Privilege Escalation**: Apps may have vulnerabilities that allow attackers to escalate their privileges and gain access to sensitive functionality or data that they shouldn't have access to.

To mitigate access control issues in Android applications, developers should follow best practices such as:
- Implementing strong authentication mechanisms, such as username/password or biometric authentication.
- Enforcing proper authorization checks throughout the app to ensure that users only have access to functionality and data they are authorized to access.
- Using secure communication protocols, such as HTTPS, to transmit sensitive data over the network.
- Encrypting sensitive data before storing it on the device and storing it in secure locations, such as the device's internal storage with proper file permissions.
- Implementing proper access controls for all app components, including activities, services, and content providers.
- Regularly testing the app for security vulnerabilities, including access control issues, and promptly addressing any issues discovered.

---
### Assessment ###

**Objective**: You are able to access the API credentials when you click the button. Now, try to access the API credentials from outside the app.

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "AccessControl1Activity".

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/910bd72d-5867-4404-889c-633fc89fd3f7)

The vulnerability in the code lies in the `viewAPICredentials()` method.

```java
    i.setAction("jakhar.aseem.diva.action.VIEW_CREDS");
```

The vulnerability arises from the lack of proper access control checks before invoking the `VIEW_CREDS` action via an implicit intent. This allows any app installed on the device that declares support for handling the `VIEW_CREDS` action to intercept and handle this intent, potentially leading to unauthorized access to sensitive API credentials.

To mitigate this vulnerability, the app should implement proper access control checks to ensure that only authorized components can handle sensitive actions. This can be achieved by using explicit intents with custom permissions or by implementing other access control mechanisms as per the app's requirements.
  
---
### Proof of Concept ###

For reference, this is how the user is inteded to obtain their API key.

|     |     |
| --- | --- |
| ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/8c1bf9cc-397c-4fd8-8380-e39ea7409ea7) | ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/0d52bdf4-d7f4-4fdd-9c2d-01b8589966ab) |

Using Drozer to assist in analyzing this - I will be using the Drozer Docker image and will outline how to have Drozer within Docker to be able to access the emulated Android device within Android Studio. Also, download the drozer-agent.apk that is to be installed on the emulated Android device from [WithSecureLab's GitHub](https://github.com/WithSecureLabs/drozer-agent/releases). Used **adb push** to upload the apk to the emulated Android device. 

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/ceadb6b3-b49d-43aa-8b8f-29e8f3736436)

From the emulated Android device within Android Studio, launch the drozer app. Once it launches, you’ll need to turn on the Embedded Server by click on the button on the lower right. 

|  Finding Drozer  | Starting Embedded Server   |
| --- | --- |
| ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/ad7c9650-b664-4a83-9713-8bf0fe152489) | ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/cef52bd5-04c0-4785-be49-fbb90b15e52c) |

The drozer agent on the emulated Android device will start listening on 127.0.0.1:31415 on the local kali machine. This is the port that we’ll later need to connect to from drozer running within docker. We’ll have to do some port remapping later using socat to have it available on 0.0.0.0:31415 so that docker can access it. 

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/6b3bc424-57b4-4271-8ca7-65c2e095b52c)

Note that it's listening on loopback 127.0.0.1

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/f93b51fe-07b1-4f3b-8e36-92be18d22522)

Now use socat to remap 127.0.0.1:31416 to 0.0.0.0:31415 - this is so docker can access it. 

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/756db55f-0bc0-48cd-ab72-aec5969dc4a0)

Note now that we’re now using socat to listen on 0.0.0.0:31415, which is being passed to 127.0.0.1:31416, which abd is forwarding to the drozer agent at 127.0.0.1:31415 on the emulated Android device. 

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/e8f7355f-8869-4875-9c79-f5d55baa0f4e)

Starting Drozer within Docker - note, you need to have docker installed... Note that if the image has not been previously downloaded, docker will automatically do so. 
- docker run -it --add-host host.docker.internal:host-gateway yogehi/drozer_docker 

In the docker container’s terminal, use the drozer console command to connect to the drozer embedded server we installed/started on the emulated Android device within Android Studio. 
- drozer console connect --server host.docker.internal

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/9d93b9c6-49d3-42a3-baa0-e0a27319232f)

Once connected, we can now user Drozer to analyze the DIVA app hosted on the emulated Android device, the path looks like Drozer Docker container -> socat -> adb forwarder -> emualted Android drivie -> drozer agent apk [embedded server].

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/c94ce2a4-ab45-40d6-a8e0-0570060a7f5c)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/e0d60d8b-0abc-4717-96f8-ef2ca49f422d)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/24e15471-20ca-4af9-b1ad-e58157ae848c)

The following command auto-launched the app and showed the Vendor API Credentials. 
![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/1409be4f-0237-4c3d-8c0c-990424b7906a)
![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/6b3a5d86-8f22-4894-b68e-df7cd0abfbad)

---
---
## Access Control Issues - Part 2
[Back to Table of Contents](#table-of-contents)

Reference [Access Control Issues - Part 1](#access-control-issues---part-1) for a description about this vulnerability.

---
### Assessment ###

**Objective**: You are able to access the Third Party app TVEETER API credentials after you have registered with Tveeter. The App requests you to register online and the vendor gives you pin, which you can use to register with the app. Now, try to access the API credentials from outside the app without knowing the PIN. This is a business logic problem so you may need to see the code.

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "AccessControl2Activity".

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/5d85f989-6be9-46e5-b294-fafbb96493b9)

The vulnerability in the provided code is in the `viewAPICredentials()` method, specifically in the following line:

```java
i.putExtra(getString(R.string.chk_pin), chk_pin);
```

This line adds a boolean extra to the intent `i` with the key obtained from `getString(R.string.chk_pin)`. The key is likely derived from a string resource, but without context, it's unclear what value it holds
The issue arises from the fact that the intent `i` is sent without proper validation or authorization checks. The app does not verify whether the user is authorized to view API credentials before sending the intent.

Without proper access control checks, any user of the app can trigger this action and potentially view sensitive API credentials. This can lead to unauthorized access to sensitive information.

To mitigate this vulnerability, access control checks should be implemented to ensure that only authorized users can view the API credentials. This could involve requiring authentication or enforcing specific permissions before allowing access to this functionality. Additionally, sensitive data such as API credentials should not be passed directly via intents without proper encryption or other security measures.

---
### Proof of Concept ###

For reference, when you checkbox 'Register Now' and click on 'View Tveeter API Credentials', it will ask you to enter a pin (Screenshots 1 & 2). When you checkbox 'Already Registered' and click on 'View Tveeter API Credentials', it will show you the 'Twitter API Credentials' - I assume this part is a bug as I've never registered (Screenshots 3 & 4).

| Screenshot 1 | Screenshot 2  | Screenshot 3 | Screenshot 4 |
| --- | --- | --- | --- |
| ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/3856ac7d-d3a7-409f-8a33-1c8fcbb8b03d) | ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/0ecd0414-a8bd-4f1f-938c-a95ea0298613) | ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/7c3f10f9-b07e-4d6e-aeac-f1f097280cab) | ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/6c6d0b51-6ce8-4aaf-98ff-45ca24542d05) |

As the presumed intent is to bypass how the DIVA app verifies the pin and access the 'Tveeter API Credentials' externally, so we need to analyze the code to determine how pin validation is done. The vulnerable code above uses the value of 'chk_pin', and further searching for 'chk_pin' within jadx-gui reveals **<string name="chk_pin">check_pin</string>**.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/8feaa88c-4857-4575-af2a-fee275fed91b)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/5b78d9f7-5b86-4ce6-8807-328dab51dd16)

We're able to access the 'Tveeter API Credentials' externally using **adb shell** - presumably the intention was to view the credentials without ever registering [despite the "bug" mentioned above]. The following command will automatically launch the 'Tveeter API Credentials' section within the emualated Android device. Note that because we're suppose to provide a valid pin to view the 'Tveeter API Credentials', we need to pass 
- adb shell am start -n jakhar.aseem.diva/.APICreds2Activity -a jakhar.aseem.diva.action.VIEW_CREDS2 --ez check_pin false
- [be sure to reference the Note below the images...]

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/9685029c-b61b-476a-bea9-bcb3a2368c07)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/83a21615-dc83-4b5f-aaa9-d8d58ab1d928)

Note: Hopefully you noticed that the --ez flag called was 'check_ping' and not 'chk_pin' (as shown in the 'AccessControl2Activity' code). This took a small bit of digging into - let's see if I can adequately describe why

The discrepancy between the resource name 'chk_pin' and the value 'check_pin' found in the string resources suggests that the app is internally using 'check_pin' as the key to retrieve the boolean extra from the intent.

When an app retrieves a string resource using `getString(R.string.chk_pin)`, it gets the value associated with the resource name 'chk_pin' defined in the XML resource files. However, the actual value of the resource is 'check_pin'.

Therefore, when passing the boolean extra via adb shell command, you need to use the key 'check_pin' to match the actual value expected by the app internally. Using 'chk_pin' will not work because it does not match the key expected by the app to retrieve the extra value from the intent.

In short, even though the resource name is 'chk_pin', the value associated with it is 'check_pin', which is the key expected by the app to retrieve the boolean extra. Hence, you need to use 'check_pin' in the adb shell command to ensure compatibility with the app's internal logic.

---
---
## Access Control Issues - Part 3
[Back to Table of Contents](#table-of-contents)

Reference [Access Control Issues - Part 1](#access-control-issues---part-1) for a description about this vulnerability.

---
### Assessment ###

**Objective**: This is a private notes application. You can create a PIN once and access your notes after entering the correct pin. Now, try to access the private notes from outside the app without knowing the PIN.

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "AccessControl3Activity".

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/de00d5d6-8c41-47d6-958c-cb1ecf5b42b8)

The vulnerable section of the code resides within the addPin method:

```java
// Vulnerable section:
spedit.putString(getString(R.string.pkey), pin);
spedit.commit();
```

The vulnerability arises from the fact that anyone can add or change the PIN without proper authentication. There are no checks to ensure that the user setting the PIN is authorized to do so. Consequently, any user of the app can set their own PIN to access private notes, regardless of whether they should have access.

To exploit this vulnerability, an attacker could simply navigate to the activity and set a PIN, granting themselves unauthorized access to private notes.

To mitigate this vulnerability, proper authentication and authorization mechanisms should be implemented before allowing users to set or change the PIN. This could involve requiring users to authenticate themselves using a password or other means before allowing them to set the PIN. Additionally, access controls should be enforced to ensure that only authorized users can access private notes protected by the PIN.

---
### Proof of Concept ###

As stated above, the app allows any user to set the pin. Then the user can click on 'Go To Private notes' to view the notes. That said, someone can access the contents externally using **adb shell** (example further below).

| Create/Change Pin | Go To Private Notes | View of Private Notes |
| --- | --- | --- |
| ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/cfd9aec7-bae2-402c-9a47-0bda2a067b27) | ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/acd08c10-7f70-4256-ba0b-85e266560015) | ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/9d8c91ae-0129-4d47-991d-4acab3fc7534) |

Using **adb shell**, we can also access the notes without providing the pin.
- content://jakhar.aseem.diva.provider.notesprovider/notes/

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/aae73c0e-7f96-4bb9-8f1a-70cedbdff25e)

Alternatively, you can also access the 'DIVA Private Notes' using **adb shell**, then navigating to the insecure sqlite3 database and accessing them without credentials.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/79c23c40-899b-47e2-98a8-3cf5403210f6)

With unauthenticated access to the sqlite3 divanotes.db database, and without 'authorization' you can insert new or modify the notes.
| Database Insert | DIVA Private Notes |
| --------------- | ------------------ |
| ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/f9187f25-0fdb-42a6-ab81-87de7093d553) | ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/7860a1d3-5c63-4aa3-bc5d-4d75bc91bd19) |

Worse yet... you could just drop the table and cause the DIVA Application to crash when attempting to access the "DIVA Private Notes'.
| Drop Table | DIVA Crash |
| ---------- | ---------- |
| ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/3bf616b2-7612-4f6b-aaf0-da929a7121fd) | ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/61bfa8e1-1055-431f-81fe-efa2fd8d2b48) |

---
---
## Hardcoding Issues - Part 2
[Back to Table of Contents](#table-of-contents)

Reference [Hardcoding Issues - Part 1](#hardcoding-issues---part-1) for a description about this vulnerability.

---
### Assessment ###

**Objective**: Find out what is hardcoded and where.

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "Hardcode2Activity".
| Harcode2Activity Code | DivaJni Code | 
| --------------------- | ------------ |
| ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/82420584-7a99-47a0-831e-b23e8e8a9cc7) | ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/a9ba9cb0-bc12-4243-88d6-509ab626e6f9)
 |

The vulnerable section of the code within Hardcode2Activity is:

```java
this.djni = new DivaJni();
```

This line instantiates a `DivaJni` object without dynamically retrieving sensitive information, such as API keys or credentials, from secure storage. Instead, the sensitive information is hardcoded directly into the `DivaJni` class or its native code implementation, making it easily accessible to anyone who reverse engineers the application.

The vulnerable section of the code within DivaJni is:

```java
private static final String soName = "divajni";
```

Here, the name of the native library (`divajni`) is hardcoded directly into the Java class. This exposes the library name to potential attackers, making it easier for them to locate and analyze the native code for vulnerabilities or sensitive information. Hardcoding sensitive information like this can pose a security risk, especially if the library contains secrets or credentials.

I've opted to use Ghidra to further decompile the DivaApplication.apk.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/ed670f66-32c1-49e2-a1bf-5a7b7468d616)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/2898b59e-3504-470c-8536-ca97439df26d)

Creating a 'New Project' called `DIVA App`.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/caa8fcd1-858b-49fe-b3b3-c9a901ae1bfa)

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/7bfe532d-6775-47c9-bc15-d144c9699b0b)

Then located the DivaApplication.apk within my Downloads directory via the GUI, and dragged & dropped the apk into the newly created Ghidra project called 'DIVA App'. It takes a moment complete 'Adding Source Files'. After finishing, I clicked on 'Batch' import.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/bfe27b76-988e-4926-b582-bf9b6cbd0b75)

The file apk will be imported.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/8e6a215f-a0b9-4e82-80ae-9d57fbdd176c)

Changed the `Depth limit` to 10, then clicked on 'Rescan'. Followed by clicking the 'OK' button at the bottom when it finished.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/fee346a2-dbfe-4a31-8563-67fe984ef4be)

The 'Batch Import Task' will start importing the apk [this will take a moment... get a coffee and sit back...] and provide a summary afterwards.

| Batch Import Task | Batch Import Summary |
| ----------------- | -------------------- |
| ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/5151cce5-fc31-4083-bde3-4fa1fe634cf1) | ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/d61f035f-44ba-4518-99ad-51f010f9024f) |

Within the 'Tree View' tab, navigate down to DIVA App -> DivaApplication.apk -> lib -> x86_64, and double-click on  libdivajni.so. This will open up the library in Ghidra's CodeBrowser. 

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/dc7aa846-4b14-46d8-bdfd-4b93a2b93a62)

It will then prompt you to Analyze the code - click on 'Yes'.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/6caf4b97-6d48-4762-b4e7-57d47e527bc2)

Then click on Analyze.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/daa9e150-6c5e-4cce-9699-96cfe9e30d33)

Go ahead and explore the libdivajni.so library to see what you can identify as being hardcoded. Eventually I identied the following: on left side within the 'Symbol Tree' panel, expand the 'Functions' directory and click on 'Java_jakhar_aseem_diva_DivaJni_access' - click on it. You will be able to see the value `olsdfgad;lh` was hardcoded.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/ea0b9778-98ad-4d24-b4ee-888aaab30160)

The issue with "olsdfgad;lh" being hardcoded within the native code of the `libdivajni.so` library is that it exposes a sensitive value directly in the compiled binary. This can lead to several security risks:

1. **Revealing Sensitive Information**: Hardcoding sensitive information like passwords or keys directly into the code makes it easily accessible to anyone who can access the binary, such as reverse engineers or attackers.

2. **Difficulty in Rotation or Updating**: If the hardcoded value needs to be changed (e.g., in case of a password rotation or key update), it requires modifying and recompiling the native code, which may not be feasible in all situations.

3. **Increased Attack Surface**: Attackers can easily locate and extract the hardcoded value from the binary, enabling them to potentially exploit the application or gain unauthorized access to sensitive resources.

To mitigate this issue, sensitive information should be stored securely and retrieved dynamically at runtime from a secure source, such as encrypted configuration files, secure storage, or server-side APIs. Hardcoding sensitive values directly into the code should be avoided whenever possible to reduce the risk of exposure and improve the overall security posture of the application.

---
### Proof of Concept ###

As identified within the assessment above, I input the password `olsdfgad;lh` into the DIVA Application and was granted access... Note that it just provides you a message that the password was accepted and doesn't navigate you elsewhere.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/87fdbc9e-291b-465d-acab-1a0acf10760e)

---
---
## Input Validation Issues - Part 3
[Back to Table of Contents](#table-of-contents)

Reference [Input Validation Issues - Part 1](#input-validation-issues---part-1) for a description about this vulnerability.

---
### Assessment ###

**Objective**: This is a Missle Launch App. Spread love not War! DOS the Damn thing! Your objective here is to NOT find the code and then launch the missiles, rather it is to crash the app (and then find the root cause of the crash).

In the jadx-gui, reference [here](#insecure-logging) on how to launch it, you can see the vulnerable code associated with "InputValidation3Activity".

I decided to lauch **adb logcat** to view the Android's system logs when I put in a wrong password to see if it reveals anything - in this case eight (8) A characters.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/6fbe492f-78bf-43c9-b35e-5670957dd66d)

- `adb logcat` outputs the following:

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/6a2068e4-b5b8-42c8-aa15-3a341b287a78)

Since I didn't see anything of interest in the Android system logs, and since the hint referenced 'a classic memory corruption vulnerability', I decided to check if there was a buffer overflow that I can exploit. That said, since computers are binary, I decided to input characters in base-2... ie: 2, 4, 8, 16, 32, 64... then work backwards as necessary.

Submitted sixteen (16) A characters, nothing of interest in the Android system logs, other than 

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/14a84314-a7b0-4ff2-93fa-2504a824dacc)

...not showing every attempt between 17 and 30 characters...

Submitted thirty-one (31) A characters would crash it - it does not. That said, notice the 

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/d524eee8-567b-4329-a9c4-659ae8d3522d)

Submitted thirty-two (32) A characters as the password, and the DIVA Applicaiton crashes.

| `abd logcat` (Android system logs) | Crashed DIVA App |
| ---------------------------------- | ---------------- |
| ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/4f35a5d9-3ef7-4aba-a4a5-0eed007c7399) | ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/c9770f0e-356c-4b03-aa8b-095fec55249d) |

Notice that a DEBUG enteries were output within the Android system logs, and that 'Fatal signal 11' when the DIVA App crashes - 0x41414141 is hex for AAAA.

```bash
05-15 13:26:04.096 14396 14396 F libc    : Fatal signal 11 (SIGSEGV), code 2, fault addr 0x41414141 in tid 12841 (khar.aseem.diva)
// TRIMMED //
05-15 13:26:04.172 14428 14428 F DEBUG   : signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x41414141
05-15 13:26:04.172 14428 14428 F DEBUG   :     eax 00000000  ebx 41414141  ecx 00000006  edx 00000000
05-15 13:26:04.172 14428 14428 F DEBUG   :     esi 41414141  edi 41414141
05-15 13:26:04.172 14428 14428 F DEBUG   :     xcs 00000073  xds 0000007b  xes 0000007b  xfs 0000003b  xss 0000007b
05-15 13:26:04.172 14428 14428 F DEBUG   :     eip a316ca00  ebp bfba7e8c  esp bfba7e40  flags 00010287
// TRIMMED //
```

After a bit of tessting, I ended up deciding to send an input twenty-four (24) A characters, followed by sets of four (4) of ABCDEFGH [AAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH] (ref the hex chart below) - the DIVA App crashes as expected. This was done to see what else I can see within the Android system logs DEBUG lines.

|  A  |  B  |  C  |  D  |  E  |  F  |  G  |  H  |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0x41 | 0x42 | 0x43 | 0x44 | 0x45 | 0x46 | 0x47 | 0x48 |


| `abd logcat` (Android system logs) | Crashed DIVA App |
| ---------------------------------- | ---------------- |
| ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/5569c85d-79f7-484d-9bdf-c546a423efc9)
 | ![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/2054d1b0-4364-4b1c-9016-2bba53c0032a) |


Notice the following for the fault address and CPU jump locations that correlated with A(41), B(42), C(43), D(44). I don't see anything with E(45) or higher. So that's just AAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDD, thirty-two (32) to crash it, and a total of thirty-six (36) to see what's in the CPU jump locations, with sixteen (16) AAAABBBBCCCCDDDD characters or sixteen (16) hex-pairs 0x41414141424242424343434344444444.

```bash
05-15 13:56:31.309 15082 15082 F libc    : Fatal signal 11 (SIGSEGV), code 2, fault addr 0x44444444 in tid 15082 (khar.aseem.diva)
// TRIMMED //
05-15 13:56:31.417 15107 15107 F DEBUG   : signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x44444444
05-15 13:56:31.417 15107 15107 F DEBUG   :     eax 00000000  ebx 41414141  ecx 00000006  edx 00000004
05-15 13:56:31.417 15107 15107 F DEBUG   :     esi 42424242  edi 43434343
05-15 13:56:31.418 15107 15107 F DEBUG   :     xcs 00000073  xds 0000007b  xes 0000007b  xfs 0000003b  xss 0000007b
05-15 13:56:31.418 15107 15107 F DEBUG   :     eip 44444444  ebp bfba7e8c  esp bfba7e40  flags 00010287
TRIMMED //
```
=============I'll need to attach a debugger to the emulated Android device, to proceed further. Using 'adb shell', we'll have the Adnroid device listen on port 4444 by determining the diva process ID and attaching it using gdbserver. Note that it doesn't have to be port 4444, it can be whatever.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/5e828d8a-fdc2-4131-8938-5227bcca66c2)

In a separate terminal, use 'adb' to foward the emulated Android device's listening port of 4444 to the of 4444 on the kali host.

![image](https://github.com/high101bro/DIVA-Assessment/assets/13679268/271ddebd-b594-4aa2-a129-e6d989e93165)


==============Make sure you are root, then we will attached the application PID with gdbserver so now we can just connect remotely, but before that we need to forward the port
Open another terminal and run this command with the port you specified
[adb forward tcp:8888 tcp:8888] you may need root permission to run all these commands, so if you face any permission issued don’t forget to run [adb root] before doing all steps

---
### Proof of Concept ###



