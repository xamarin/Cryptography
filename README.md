#Introduction#
This project groups some crypto classes that were previously part of **SSH.NET**, and makes them available for a broad set of target frameworks.

#Hash algorithms#

**SshNet.Security.Cryptography** features the following hash functions:
* md5
* sha1
* sha2-256
* sha2-384
* sha2-512
* ripemd160

#Message Authentication Code#

**SshNet.Security.Cryptography** includes the following MAC algorithms:
* hmac-md5
* hmac-sha1
* hmac-sha2-256
* hmac-sha2-384
* hmac-sha2-512
* hmac-ripemd160

#Framework Support#
**SshNet.Security.Cryptography** is available for the following target frameworks:

Target Framework Moniker  | Frameworks
:------------------------ | :--
netstandard1.0            | .NET Platform Standard 1.0
netstandard1.3            | .NET Platform Standard 1.3
net20                     | .NET Framework 2.0
net40                     | .NET Framework 4.0
net45                     | .NET Framework 4.5
portable-net45+win8+wpa81 | .NET Framework 4.5<br>Windows 8<br>Windows Phone 8.1
sl4                       | Silverlight 4
sl5                       | Silverlight 5
uap10.0                   | Universal Windows Platform 10
wp71                      | Windows Phone Silverlight 7.1
wp8                       | Windows Phone Silverlight 8.0

In our codebase, we use the following conditional compilation symbols to identity features supported by a given target framework:

Symbol                       | Description
:----------------------------| :--------------------------------------------------------------------------------
FEATURE_CRYPTO_HASHALGORITHM | [HashAlgorithm](https://msdn.microsoft.com/en-us/library/system.security.cryptography.hashalgorithm.aspx) and [KeyedHashAlgorithm](https://msdn.microsoft.com/en-us/library/system.security.cryptography.keyedhashalgorithm.aspx) classes are available

#Build#
The following software is required to build **SshNet.Security.Cryptography** in all its supported flavors:

Software                          | net35 | net40 | net45 | sl4 | sl5 | wp71 | wp8 | portable-net45+win8+wpa81 | uap10.0 | netstandard1.0 | netstandard1.3
--------------------------------- | :---: | :---: | :---: | :-: | :-: | :--: | :-: | :-----------------------: | :-----: | :------------: | :------------:
Windows Phone SDK 8.0             |       |       |       | x   | x   | x    | x   | x                         |         |                |               
Visual Studio 2012 Update 5       | x     | x     |       | x   | x   | x    | x   |                           |         |                |               
Visual Studio 2015 Update 3       | x     | x     | x     |     | x   |      | x   | x                         | x       | x              | x             
.NET Core 1.0 Visual Studio Tools |       |       |       |     |     |      |     |                           |         | x              | x             

**Note:**

Where possible, we use the **Shared Project** concept - which was introduced in **Visual Studio 2015** - to share code between *flavors* of **SshNet.Security.Cryptography**.
To avoid maintaining two sets of project files, these projects can only be built in **Visual Studio 2015** (or higher).
