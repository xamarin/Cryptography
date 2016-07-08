using System;
using System.Text;
using SshNet.Security.Cryptography.Common.Tests;
using Xunit;

namespace SshNet.Security.Cryptography.Tests
{
    /// <summary>
    /// Test cases are from https://tools.ietf.org/html/rfc2202.
    /// </summary>
    public class HMACMD5Test
    {
        [Fact]
        public void Rfc2202_1()
        {
            var key = ByteExtensions.Repeat(0x0b, 16);
            var data = Encoding.ASCII.GetBytes("Hi There");
            var expectedHash = ByteExtensions.HexToByteArray("9294727a3638bb1c13f48ef8158bfc9d");
            var hmac = new HMACMD5(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc2202_2()
        {
            var key = Encoding.ASCII.GetBytes("Jefe");
            var data = Encoding.ASCII.GetBytes("what do ya want for nothing?");
            var expectedHash = ByteExtensions.HexToByteArray("750c783e6ab0b503eaa86e310a5db738");
            var hmac = new HMACMD5(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc2202_3()
        {
            var key = ByteExtensions.Repeat(0xaa, 16);
            var data = ByteExtensions.Repeat(0xdd, 50);
            var expectedHash = ByteExtensions.HexToByteArray("56be34521d144c88dbb8c733f0e8b3f6");
            var hmac = new HMACMD5(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc2202_4()
        {
            var key = ByteExtensions.HexToByteArray("0102030405060708090a0b0c0d0e0f10111213141516171819");
            var data = ByteExtensions.Repeat(0xcd, 50);
            var expectedHash = ByteExtensions.HexToByteArray("697eaf0aca3a3aea3a75164746ffaa79");
            var hmac = new HMACMD5(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc2202_5()
        {
            var key = ByteExtensions.Repeat(0x0c, 16);
            var data = Encoding.ASCII.GetBytes("Test With Truncation");

            var expectedHash = ByteExtensions.HexToByteArray("56461ef2342edc00f9bab995690efd4c");
            var hmac = new HMACMD5(key);
            var actualHash = hmac.ComputeHash(data);
            Assert.Equal(expectedHash, actualHash);

            var expectedHash96 = ByteExtensions.HexToByteArray("56461ef2342edc00f9bab995");
            var hmac96 = new HMACMD5(key, 96);
            var actualHash96 = hmac96.ComputeHash(data);
            Assert.Equal(expectedHash96, actualHash96);
        }

        [Fact]
        public void Rfc2202_6()
        {
            var key = ByteExtensions.Repeat(0xaa, 80);
            var data = Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First");
            var expectedHash = ByteExtensions.HexToByteArray("6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd");
            var hmac = new HMACMD5(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc2202_7()
        {
            var key = ByteExtensions.Repeat(0xaa, 80);
            var data = Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data");
            var expectedHash = ByteExtensions.HexToByteArray("6f630fad67cda0ee1fb1f562db3aa53e");
            var hmac = new HMACMD5(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void SetKetShouldResetHashProvider()
        {
            // Rfc2202_7
            var key = ByteExtensions.Repeat(0xaa, 80);
            var data = Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data");
            var expectedHash = ByteExtensions.HexToByteArray("6f630fad67cda0ee1fb1f562db3aa53e");
            var hmac = new HMACMD5(key);

            var actualHash = hmac.ComputeHash(data);
            Assert.Equal(expectedHash, actualHash);

            // Rfc2202_2
            key = Encoding.ASCII.GetBytes("Jefe");
            data = Encoding.ASCII.GetBytes("what do ya want for nothing?");
            expectedHash = ByteExtensions.HexToByteArray("750c783e6ab0b503eaa86e310a5db738");

            hmac.Key = key;
            actualHash = hmac.ComputeHash(data);
            Assert.Equal(expectedHash, actualHash);
        }
    }
}
