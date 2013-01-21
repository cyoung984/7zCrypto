7zCrypto
========

Adds a keyfile to 7z archives which contains the password for the archive. The password is encrypted with RSA and as such a matching private key is required to decrypt the archive.

Building:
=========
Both Boost and crypto++ are required. You can refer to their documentation for both downloads and installation instructions. 
On Linux edit the makefile to reflect your directories. On Windows you need to add a property sheet to Visual Studio.

Usage:
======
At the moment OpenSSL keys aren't supported, only crypto++ keys are. They can be generated as follows.
Command line arguments aren't currently forwarded to 7zip. 

$ 7zCrypto.exe g
Key length in bits : 2048
Public key file : key.pub
Private key file : key.prv

Then, to generate and add a keyfile to an archive..
Note: You need to have 7za (7-zip) in the same directory as 7zCrypto.

$ 7zCrypto.exe a
7z archive : archive.7z
Archive password : password

Checking password...

Enter the paths to public key files you wish to use. Send EOF when done.

Public key file : key.pub

Public key file : ^Z


The key file was successfully added to 'archive.7z'
It can now be decrypted with any matching private keys

That is for windows, on Linux you would do CTRL + D instead of Z to signal no more keys.

Finally, to decrypt an archive with your private key...

$ 7zCrypto.exe e
Archive : archive.7z
Private key: key.prv

The archive was successfully extracted

