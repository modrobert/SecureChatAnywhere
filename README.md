# SecureChatAnywhere

![SecureChatAnywhere](https://raw.githubusercontent.com/modrobert/SecureChatAnywhere/master/SecureChatAnywhere_main.gif)
 
## Encrypts/decrypts chat messages with AES-128/CBC.

### Copyright (C) 2018  Robert V. <modrobert@gmail.com>
### Software licensed under GPLv3.

---
 
### Features

* AES-128/CBC encryption with Base64 output
* Works with any text based apps and online services
* Handles multiple keys as needed
* Output copied to clipboard automatically
* UTF-8 support enforced
* Log window provides detailed overview of recent actions
* Compatible with pretty much any Java JRE from the past decade
* Lean and mean, release jar ~30kb in size

---

### Description

SecureChatAnywhere is a lightweight program written in Java with the purpose of 
making it easy to encrypt and decrypt any kind of text messages using
AES-128/CBC symmetric encryption. The graphical user interface (GUI) is
designed as a convenient "copy & paste tool" for computers to manage encryption
and decryption stand-alone, in other words without relying on any kind of
external communication.

This is not intended to secure all messages in a chosen chat platform/service,
that would be cumbersome, it's meant to secure the sensitive data such as
sharing login/password info, home address, bank details, personal life, health
issues, business decisions, projects in development, or any other messages
where privacy and secure communication is needed.

The encrypted data (ciphertext) output is in Base64 format which makes
SecureChatAnywhere compatible with any kind of text based internet
communication tools out there such as email, chat clients and online services.

For example (but not limited to):

* Gmail
* Hotmail (Outlook)
* Twitter
* Google Plus
* Facebook
* Skype
* Line
* Wire
* WhatsApp
* Telegram
* Signal
* IRC
* Discord

---

### Installation

Create a directory, unzip the release and copy the included 
SecureChatAnywhere_beta.jar to it, along with the startup script (.sh) or batch
file (.bat) for your operating system. If you are not using a startup script
(.bat file), in order to make sure there is full UTF-8 encoding support you
need to run the program as follows:

java -Dfile.encoding=UTF-8 -jar SecureChatAnywhere_beta.jar

There is also a built-in test that will refuse to launch the program if the
file encoding used differs from UTF-8. This important because decrypting
ciphertext with the wrong character encoding can result in unpredictable
results where the plaintext can't be read.

If you wish to compile and run the program yourself instead of using the
precompiled jar file, then use the following commands.

Compile:  
javac SecureChatAnywhere.java

Run:  
java -Dfile.encoding=UTF-8 SecureChatAnywhere

---

### Usage

#### General:

The basic concept here is to copy & paste text as conveniently as possible, 
which is still an inefficient way to communicate. This is the reason
SecureChatAnywhere is only suitable for the messages you really want to keep
private. On the other hand, personally I think this is a small price to pay in
order to stay in control of the keys and being able to encrypt messages.

#### Key handling:

SecureChatAnywhere uses AES-128/CBC which is [symmetric encryption](https://en.wikipedia.org/wiki/Symmetric-key_algorithm) with a cryptographic
key, you can create the 128 bit key yourself from 32 chars of hexadecimal
number or use the built-in "Generate key" to call a secure random method in
Java which was designed for the purpose of generating random keys for AES
encryption, it's up to you. 

In order to encrypt messages and send to another person you need to share a
secret key, so the person you send the encrypted messages have a way to decrypt
them. The way you share the secret key will determine how secure the future
communication will be. For example, finding a way to share the key with the
person by meeting physically will be safer than using internet to send it.
Writing the key by hand on a piece of paper and handing it over in person will
be safer than using an app on your smartphone (which is compromised by design).
You can generate and share different keys with several people or share the same
key to a group of people, it all depends on who you want to be able to decrypt
your messages.

SecureChatAnywhere allows you to create a label for each key used and it is
stored in the plain text file SecureChatAnywhere.key.txt. The file format is
simple, one line/row for each key, in the format 'name=aabbccddeeff001122..',
when using the tool the name of the unique key (label) will be used, not
mentioning the actual key except when using key related functions in the
program.

Make sure the key label is unique for each key, don't use spaces, and keep the
label text below 15 characters. Although it is possible to add UTF-8 escape
sequences for the key label I advice against it because it breaks the sorting
of the keys. You can however use UTF-8 characters when encrypting chat messages
which will be decrypted correctly.

If you do changes to the SecureChatAnywhere.key.txt file you need to quit the
program and restart it for the changes to take effect. This is something I
hope to improve in future versions of the program, but for now, lets keep it
simple.

When SecureChatAnywhere is launched for the first time it will create the file
SecureChatAnywhere.keys.txt (if it is missing) in the same directory as the
program is residing, and generate three random keys; key01, key02 and key03.
The keys are created using the
[KeyGenerator](https://docs.oracle.com/javase/8/docs/api/javax/crypto/class-use/KeyGenerator.html) class in Java which provides random data similar to
SecureRandom but is specifically intended for cryptographic keys. You can add
your own keys to the SecureChatAnywhere.keys.txt file, or edit/remove existing
ones. The keys provided are just added to get you started and familiar with the
key format. Feel free to edit, remove or add keys as needed.

The way you are able to control the keys yourself without obfuscation in this
tool is unique and a deliberate design decision. I want you, the user, to have
full control, this comes at the price of leaving you in charge of handling the
keys in a secure manner, not the program. Think carefully when you decide to
share a cryptographic key with someone. Ask yourself: Who could potentially see 
the key besides the person I want to share it with? Security like this is hard
to get right, it's easy to do mistakes which compromises the key, but it's even
worse when you have no control of the keys at all, which is true for most of
the current chat/message systems online. 

#### The graphical user interface (GUI):

The GUI layout is designed as follows; all plaintext (decrypted) data is
handled in the left pane window, the ciphertext (encrypted) data is handled in
the right pane window. The lower pane is the log window, all actions will be
logged here including the plaintext and ciphertext generated. Note that this
is not logged to file, when quitting program any information in the log window
will be lost.

When pasting the ciphertext in Base64 format to be decrypted any spaces or line
breaks are ignored.

#### Menu functions:

Action ->
 
Encrypt - Encrypts the current plaintext with the selected key and copies the
output to clipboard.  
Decypt - Decrypts the current ciphertext with the selected key and copies the
output to clipboard.  
Clear - Clears both left and right window panes.  
Generate key - This will create a random AES 128 bit key using the [KeyGenerator](https://docs.oracle.com/javase/8/docs/api/javax/crypto/class-use/KeyGenerator.html) class in Java.  
List keys - Lists current keys as parsed from SecureChatAnywhere.keys.txt
during program launch.  
Edit keyfile - Will use the desktop function to open the
SecureChatAnywhere.keys.txt file using the OS associated editor selected for
the txt file type.  
Quit - Quits the program.  
 
Help ->
 
About - Show program information. 

#### Middle pane buttons:

<<- Encrypt - Encrypts the current plaintext with the selected key and copies
the output to clipboard.  
Decrypt ->> - Decrypts the current ciphertext with the selected key and copies
the output to clipboard.  
<<- Clear - Clears the left pane with plaintext.  
Clear ->> - Clears the right pane with ciphertext.  
|"Key selector"| - When clicked or held, this button lets you select the
key used when encrypting and decrypting.  

---

### Security

The idea is to be able to use any text based communication service on internet
regardless if trusted or not and add secure encryption on top of that without
any external dependencies or authentication. In effect removing the need to
access the internet when encrypting the data (plaintext). This simple tool is
provided with source code so the methods used can be scrutinized openly.

The design choices may seem awkward compared to existing conventional tools,
this is due to the primary goals; to isolate and give the user full control of
handling and storing the encryption keys used with this program.

The conclusion is that this can be as secure as the user wants it to be. If the
user wants to share his/her key on a piece paper hand delivered in person then
so be it, if the user choose a less secure method such as sending the key
through a trusted internet service then so be it. If the user decides to store
this program and key file on an SD card, USB stick or an encrypted hard drive
it is his/her decision. Again, the user is in full control of the software and
keys used. 

SecureChatAnywhere does not provide any security measures on the computer
(localhost) where the user run the program, there are no attempts to obfuscate
the keys in memory while executing or on disk. The keys are stored in plain
text hex format in the 'SecureChatAnywhere.keys.txt' file residing in the same
directory as the program. Keys can be added, deleted, and edited as needed
using any text editor or tool the user deem fit.

If you are interested the encryption and decryption used in SecureChatAnywhere
it can be tested with the supplied Python script [aes128_cbc_pkcs5_base64.py](https://github.com/modrobert/SecureChatAnywhere/blob/master/aes128_cbc_pkcs5_base64.py).
This script is not a complete solution, just hardcoded "proof of concept" code
to test the encryption methods used.

A word of warning; although you can encrypt each message you send through a 
chosen chat service using SecureChatAnywhere, keep in mind that the metadata
may still be recorded by the underlying system. In other words, the time you
posted your message, who you identify as, and who you sent it to, can still be
recorded even if the content of your message itself remains encrypted and
secure.

---

### FAQ

Q: Isn't this project a bit paranoid? Point being, many existing chat systems
are secure even if you choose not to trust them.

A: If you aren't in control of the keys you have no security.
<br>
<br>
Q: After starting the program I noticed there are three keys to choose from,
what are they used for?

A: These keys are created the first time the program is launched and stored in
a file called SecureChatAnywhere.keys.txt which resides in the same directory
as the program. The keys are created using the
[KeyGenerator](https://docs.oracle.com/javase/8/docs/api/javax/crypto/class-use/KeyGenerator.html) class in Java which provides random data similar to
SecureRandom but is specifically intended for cryptographic keys. You can add
your own keys to the SecureChatAnywhere.keys.txt file, or edit/remove existing
ones. The keys provided are just added to get you started and familiar with the
key format. Check the "Usage" section for more information.
<br>
<br>
Q: Why aren't you using AES-256 instead of AES-128?

A: Mainly because some Java runtime environments impose restrictions on AES-256
usage and I wanted SecureChatAnywhere to be as compatible as possible across
different hardware/OS platforms. AES-128 is still considered secure with 2^128
possible keys to bruteforce, even preferred by some due to better key schedule
design.
<br>
<br>
Q: Don't store keys in plaintext, this is bad practice, shame on you.

A: Is that even a question? Anyway, the design idea is that the user decides
how to protect the keys and more importantly, where the program with keys are 
stored. The SecureChatAnywhere release jar file is roughly 30kb in size, it
will easily fit on a floppy, SD card or USB stick. SecureChatAnywhere is
intended to be used on a computer by the user locally, there is no external
server or cloud involved here. If the computer where the user runs the program
is compromised by malware or other means then no encryption will protect since
screen, mouse and keyboard events can be intercepted. Using a hardcoded key
hidden in the program to encrypt the keys in the key file is equally futile
since the source code is provided according to GPLv3.
<br>
<br>
Q: Why don't you encrypt the key file with AES using a password hashing
algorithm such as PBKDF2?

A: I thought about it long and hard, but it will make things more complicated
for the user, instead of focusing on storing and handling the actual encryption
keys you move the problem to yet another password which the user has to
remember or store somewhere. If you want to secure the key file this way I
suggest using tools designed specifically for this purpose, such as VeraCrypt,
LUKS or TrueCrypt with file container and disk encryption support, then both
the program and key file can be stored safely together while providing
plausible deniability. 
<br>
<br>
Q: Why not use [insert existing tool here] instead?

A: I wanted to explore a new approach, in an attempt to secure any kind of text
based communication tools found online.
<br>
<br>
Q: The GUI looks like shit, what is that, plain AWT?

A: Yes, ancient Java AWT, in the original spirit of "write once, run anywhere"
and keeping the program native with no external library dependencies besides
the JRE.
<br>
<br>
Q: Are you planning on porting this to Android and iOS?

A: Yes, but it's a long-term project as it involves hardware. These smartphone
platforms are already compromised by design where Google and Apple respectively
control the encryption keys, the user is locked out in a proprietary system.
I have started to design a hardware prototype using a SoC with embedded
cryptographic core where all plaintext input and output has to be controlled by
the device and the smartphone app only handles ciphertext where no trust is
required. When or if I ever finish this project it will be released as open
hardware design.

---

### Background
    
There are plenty of existing chat programs/services out there claiming to be
secure where obfuscating the user keys is common practice, keeping the users 
away from any direct control of the encryption process and keys. Sometimes the
reason for this is that all users are treated as ignorant, and the idea is to
protect them from themselves, in other cases it is because the authors of the
program/service want control of the keys to be able to decrypt the user
communicated data as needed. There are also programs/services demanding private
user details in exchange for functionality, for example requiring a valid
phone number, email address, or other types of registration undermining
privacy. 

With SecureChatAnywhere there are no requirements of personal data to function,
it respects user privacy and freedom within the boundaries of GPLv3. The
intention is to provide a simple minimalistic tool with secure encryption using
AES-128/CBC which runs on any desktop platform with Java (JRE) installed.

---

### Contribute

If you wish to contribute to this project by donating then you can do so via
Bitcoin or PayPal.

Bitcoin: 33ShPNJkT3PGegKdJiXGMMpkVyekcMaHDF

PayPal: https://paypal.me/modrobert

If you want to help by providing code fixes or adding minor functionality then
you are welcome to fork this project and create a "pull request" which will be
reviewed and "pulled" if approved.

If you want to add major changes to the program which alters the goal of the
entire project then it's better if you fork the repository, and maintain the
fork yourself. One of the project goals is to provide a lightweight program
with no dependencies besides native JRE, so keep that in mind.

---

### License

SecureChatAnywhere encrypts/decrypts chat messages with AES-128/CBC.  
Copyright (C) 2018  Robert V. <modrobert@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

