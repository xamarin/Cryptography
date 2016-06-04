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
* .NET Platform Standard 1.0
* .NET Platform Standard 1.3
* .NET Framework 2.0
* .NET Framework 4.0
* .NET Framework 4.5
* Silverlight 4
* Silverlight 5
* Windows Phone Silverlight 7.1
* Windows Phone Silverlight 8.0
* Windows 8.0
* Windows Phone 8.1
* Universal Windows Platform 10

In our codebase, we use the following conditional compilation symbols to identity features supported by a given target framework:

Symbol                       | Description
:----------------------------| :--------------------------------------------------------------------------------
FEATURE_CRYPTO_HASHALGORITHM | [HashAlgorithm](https://msdn.microsoft.com/en-us/library/system.security.cryptography.hashalgorithm.aspx) and [KeyedHashAlgorithm](https://msdn.microsoft.com/en-us/library/system.security.cryptography.keyedhashalgorithm.aspx) classes are available

#Build#
The following software is required to build **SshNet.Security.Cryptography** in all its supported flavors:

Software                          | .NET 3.5 | .NET 4.0 | .NET 4.5 | SL 4 | SL 5 | WP 71 | WP 80 | WPA 81 | WIN8 | UAP10 | .NETStandard 1.0 | .NETStandard 1.3
--------------------------------- | :------: | :------: | :------: | :--: | :--: | :---: | :---: | :----: | :--: | :---: |:---------------: | :--------------:
Windows Phone SDK 8.0             |          |          |          | x    | x    | x     | x     | x      |      | x     |                  |
Visual Studio 2012 Update 5       | x        | x        |          | x    | x    | x     | x     |        |      |       |                  |
Visual Studio 2015 Update 2       | x        | x        | x        |      | x    |       | x     | x      | x    | x     | x                | x
.NET CLI SDK Preview 1            |          |          |          |      |      |       |       |        |      |       | x                | x

**Note:**

Where possible, we use the **Shared Project** concept - which was introduced in **Visual Studio 2015** - to share code between *flavors* of **SshNet.Security.Cryptography**.
To avoid maintaining two sets of project files, these projects can only be built in **Visual Studio 2015** (or higher).
