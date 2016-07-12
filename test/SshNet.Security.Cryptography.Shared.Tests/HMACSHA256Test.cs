using System.Text;
using SshNet.Security.Cryptography.Common.Tests;
using Xunit;

namespace SshNet.Security.Cryptography.Tests
{
    /// <summary>
    /// Test cases are from http://tools.ietf.org/html/rfc4231.
    /// </summary>
    public class HMACSHA256Test
    {
        [Fact]
        public void Rfc4231_1()
        {
            var key = ByteExtensions.Repeat(0x0b, 20);
            var data = ByteExtensions.HexToByteArray("4869205468657265"); // "Hi There"
            var expectedHash = ByteExtensions.HexToByteArray("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
            var hmac = new HMACSHA256(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        /// <summary>
        /// Test with a key shorter than the length of the HMAC output.
        /// </summary>
        [Fact]
        public void Rfc4231_2()
        {
            var key = ByteExtensions.HexToByteArray("4a656665"); // "Jefe";
            var data = ByteExtensions.HexToByteArray("7768617420646f2079612077616e7420666f72206e6f7468696e673f"); // "what do ya want for nothing?"
            var expectedHash = ByteExtensions.HexToByteArray("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
            var hmac = new HMACSHA256(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        /// <summary>
        /// Test with a combined length of key and data that is larger than 64 bytes (= block-size of SHA-224 and SHA-256).
        /// </summary>
        [Fact]
        public void Rfc4231_3()
        {
            var key = ByteExtensions.Repeat(0xaa, 20);
            var data = ByteExtensions.Repeat(0xdd, 50);
            var expectedHash = ByteExtensions.HexToByteArray("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
            var hmac = new HMACSHA256(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        /// <summary>
        /// Test with a combined length of key and data that is larger than 64 bytes (= block-size of SHA-224 and SHA-256).
        /// </summary>
        [Fact]
        public void Rfc4231_4()
        {
            var key = ByteExtensions.HexToByteArray("0102030405060708090a0b0c0d0e0f10111213141516171819");
            var data = ByteExtensions.Repeat(0xcd, 50);
            var expectedHash = ByteExtensions.HexToByteArray("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
            var hmac = new HMACSHA256(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        /// <summary>
        /// Test with a truncation of output to 128 bits.
        /// </summary>
        [Fact]
        public void Rfc4231_5()
        {
            var key = ByteExtensions.Repeat(0x0c, 20);
            var data = ByteExtensions.HexToByteArray("546573742057697468205472756e636174696f6e"); // "Test With Truncation"
            var expectedHash = ByteExtensions.HexToByteArray("a3b6167473100ee06e0c796c2955552b");
            var hmac = new HMACSHA256(key, 128);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        /// <summary>
        /// Test with a key larger than 128 bytes (= block-size of SHA-384 and SHA-512).
        /// </summary>
        [Fact]
        public void Rfc4231_6()
        {
            var key = ByteExtensions.Repeat(0xaa, 131);
            var data = ByteExtensions.HexToByteArray("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374"); // "Test Using Larger Than Block-Size Key - Hash Key First"
            var expectedHash = ByteExtensions.HexToByteArray("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
            var hmac = new HMACSHA256(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        /// <summary>
        /// Test with a key and data that is larger than 128 bytes (= block-size of SHA-384 and SHA-512).
        /// </summary>
        [Fact]
        public void Rfc4231_7()
        {
            var key = ByteExtensions.Repeat(0xaa, 131);
            var data = ByteExtensions.HexToByteArray("5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e"); // "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
            var expectedHash = ByteExtensions.HexToByteArray("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
            var hmac = new HMACSHA256(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }
    }
}
