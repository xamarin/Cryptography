using System.Text;
using SshNet.Security.Cryptography.Common.Tests;
using Xunit;

namespace Renci.Security.Cryptography.Tests
{
    /// <summary>
    /// Test cases are defined in RFC 1321, section A.5
    /// </summary>
    public class MD5Test
    {
        private readonly MD5 _hashAlgorithm;

        public MD5Test()
        {
            _hashAlgorithm = new MD5();
        }

        [Fact]
        public void Rfc1321_1()
        {
            var data = Encoding.ASCII.GetBytes("");
            var expectedHash = ByteExtensions.HexToByteArray("d41d8cd98f00b204e9800998ecf8427e");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc1321_2()
        {
            var data = Encoding.ASCII.GetBytes("a");
            var expectedHash = ByteExtensions.HexToByteArray("0cc175b9c0f1b6a831c399e269772661");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc1321_3()
        {
            var data = Encoding.ASCII.GetBytes("abc");
            var expectedHash = ByteExtensions.HexToByteArray("900150983cd24fb0d6963f7d28e17f72");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc1321_4()
        {
            var data = Encoding.ASCII.GetBytes("message digest");
            var expectedHash = ByteExtensions.HexToByteArray("f96b697d7cb7938d525a2f31aaf161d0");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc1321_5()
        {
            
            var data = Encoding.ASCII.GetBytes("abcdefghijklmnopqrstuvwxyz");
            var expectedHash = ByteExtensions.HexToByteArray("c3fcd3d76192e4007dfb496cca67e13b");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc1321_6()
        {
            var data = Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
            var expectedHash = ByteExtensions.HexToByteArray("d174ab98d277d9f5a5611c2c9f419d9f");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc1321_7()
        {
            var data = Encoding.ASCII.GetBytes("12345678901234567890123456789012345678901234567890123456789012345678901234567890");
            var expectedHash = ByteExtensions.HexToByteArray("57edf4a22be3c955ac49da2e2107b67a");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }
    }
}

