using System.Text;
using SshNet.Security.Cryptography.Common.Tests;
using Xunit;

namespace SshNet.Security.Cryptography.Tests
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
            var data = new byte[0]; // ""
            var expectedHash = ByteExtensions.HexToByteArray("d41d8cd98f00b204e9800998ecf8427e");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc1321_2()
        {
            var data = ByteExtensions.HexToByteArray("61"); // "a"
            var expectedHash = ByteExtensions.HexToByteArray("0cc175b9c0f1b6a831c399e269772661");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc1321_3()
        {
            var data = ByteExtensions.HexToByteArray("616263"); // "abc"
            var expectedHash = ByteExtensions.HexToByteArray("900150983cd24fb0d6963f7d28e17f72");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc1321_4()
        {
            var data = ByteExtensions.HexToByteArray("6d65737361676520646967657374"); // "message digest"
            var expectedHash = ByteExtensions.HexToByteArray("f96b697d7cb7938d525a2f31aaf161d0");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc1321_5()
        {

            var data = ByteExtensions.HexToByteArray("6162636465666768696a6b6c6d6e6f707172737475767778797a"); // "abcdefghijklmnopqrstuvwxyz"
            var expectedHash = ByteExtensions.HexToByteArray("c3fcd3d76192e4007dfb496cca67e13b");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc1321_6()
        {
            var data = ByteExtensions.HexToByteArray("4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839"); // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            var expectedHash = ByteExtensions.HexToByteArray("d174ab98d277d9f5a5611c2c9f419d9f");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc1321_7()
        {
            var data = ByteExtensions.HexToByteArray(StringExtensions.Repeat("31323334353637383930", 8)); // "1234567890" * 8
            var expectedHash = ByteExtensions.HexToByteArray("57edf4a22be3c955ac49da2e2107b67a");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }
    }
}

