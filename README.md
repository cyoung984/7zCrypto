7zCrypto
========

Adds a keyfile to 7z archives which contains the password for the archive. The password is encrypted with RSA and as such a matching private key is required to decrypt the archive.

Building:
=========
Both Boost and crypto++ are required. You can refer to their documentation for both downloads and installation instructions. 
On Linux edit the makefile to reflect your directories. On Windows you need to add a property sheet to Visual Studio.

In addition to stock Boost an unofficial library, Boost Process, is required. Its application into Boost was rejected, but it's still useful.
It can be downloaded from http://www.highscore.de/boost/gsoc2010/process.zip
Extract the files into your Boost folders (Boost/boost and Boost/libs).

Unfortunately it was made for an older version of Boost and requires a simple modification to work with Boost 1.52.0.
Change boost/process/operations.hpp to include boost/filesystem/operations.hpp instead of boost/filesystem/path.hpp. 
Alternatively, you can download process.zip which has the required changes and is included in this repo.

Usage:
======

usage: <command> [<switches>...]

<commands>:
  a: Add keyfile to the archive
  e: Extract files from the archive
  g: Generate RSA key pair
  k: Generate the keyfile and save to disk.
<switches>:
  -pub <file>: the public key to use.
  -prv <file>: the private key to use.
  -len <positive integer>: the key length in bits
  -arc <file>: the archive to operate on.
  -p <password>: the archive's password
  -nocheck: don't verify the archive's password
  -v: verbose mode (show 7zip output)
  -keyfile <file>: use specified file as the keyfile.
  -forward: forward all following command line data to 7zip.
  
Note: You need to have 7za (7-zip) in the same directory as 7zCrypto, or in your $PATH.

OpenSSL keys are supported, but cannot be generated. Keys generated via 7zCrypto are not compatible with OpenSSL.

You can generate a key as follows. 

$ 7zCrypto.exe g
Key length in bits : 2048
Public key file : key.pub
Private key file : key.prv

Or, if you perfer command line: $ 7zCrypto.exe g -prv key.prv -pub key.pub -len 2048

Now, there are two options for generating a key file. You can generate one and include in in the target archive,
or you can use an external one. For small archives it's easier to include it within the archive because it doesn't
take long to add it. However, as 7z rebuilds the archive each time you add a file large archives it can take a
significant amount of time. The command a will add it to the archive, whereas k will generate an external file.

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
Checking the password can take a while with large archives, too. If you know you've entered the password correctly
you can specify -nocheck to disable the check. As with generating the key, adding a key can be done completely
via command line. 

$ 7zCrypto.exe a -arc archive.7z -pub key.pub -p password
or 
$ 7zCrypto.exe k -arc archive.7z -pub key.pub -p password -keyfile archive.7z.key

If you specify the public key file via command line you won't be prompted for keys and as such the keyfile will only
be built for a single key pair.

Finally, to decrypt an archive with your private key...

$ 7zCrypto.exe e
Archive : archive.7z
Private key: key.prv

The archive was successfully extracted

If you want to use an external keyfile,
$ 7zCrypto.exe e -keyfile archive.7z.key -prv key.prv -arc archive.7z
Processing key file...
Extracting archive...

The archive was successfully extracted
