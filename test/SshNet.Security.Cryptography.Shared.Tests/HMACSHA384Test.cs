using System.Text;
using SshNet.Security.Cryptography.Common.Tests;
using Xunit;

namespace SshNet.Security.Cryptography.Tests
{
    /// <summary>
    /// Test cases are from http://tools.ietf.org/html/rfc4231.
    /// </summary>
    public class HMACSHA384Test
    {
        [Fact]
        public void Rfc4231_1()
        {
            var key = ByteExtensions.Repeat(0x0b, 20);
            var data = Encoding.ASCII.GetBytes("Hi There");
            var expectedHash = ByteExtensions.HexToByteArray("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
            var hmac = new HMACSHA384(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        /// <summary>
        /// Test with a key shorter than the length of the HMAC output.
        /// </summary>
        [Fact]
        public void Rfc4231_2()
        {
            var key = Encoding.ASCII.GetBytes("Jefe");
            var data = Encoding.ASCII.GetBytes("what do ya want for nothing?");
            var expectedHash = ByteExtensions.HexToByteArray("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649");
            var hmac = new HMACSHA384(key);

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
            var expectedHash = ByteExtensions.HexToByteArray("88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27");
            var hmac = new HMACSHA384(key);

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
            var expectedHash = ByteExtensions.HexToByteArray("3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb");
            var hmac = new HMACSHA384(key);

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
            var data = Encoding.ASCII.GetBytes("Test With Truncation");
            var expectedHash = ByteExtensions.HexToByteArray("3abf34c3503b2a23a46efc619baef897");
            var hmac = new HMACSHA384(key, 128);

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
            var data = Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First");
            var expectedHash = ByteExtensions.HexToByteArray("4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952");
            var hmac = new HMACSHA384(key);

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
            var data = Encoding.ASCII.GetBytes("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.");
            var expectedHash = ByteExtensions.HexToByteArray("6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e");
            var hmac = new HMACSHA384(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }
    }
}
