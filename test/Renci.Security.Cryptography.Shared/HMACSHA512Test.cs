using System.Text;
using Renci.Common.Tests;
using Xunit;

namespace Renci.Security.Cryptography.Tests
{
    /// <summary>
    /// Test cases are from http://tools.ietf.org/html/rfc4231.
    /// </summary>
    public class HMACSHA512Test
    {
        [Fact]
        public void Rfc4231_1()
        {
            var key = ByteExtensions.Repeat(0x0b, 20);
            var data = Encoding.ASCII.GetBytes("Hi There");
            var expectedHash = ByteExtensions.HexToByteArray("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
            var hmac = new HMACSHA512(key);

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
            var expectedHash = ByteExtensions.HexToByteArray("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
            var hmac = new HMACSHA512(key);

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
            var expectedHash = ByteExtensions.HexToByteArray("fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");
            var hmac = new HMACSHA512(key);

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
            var expectedHash = ByteExtensions.HexToByteArray("b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd");
            var hmac = new HMACSHA512(key);

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
            var expectedHash = ByteExtensions.HexToByteArray("415fad6271580a531d4179bc891d87a6");
            var hmac = new HMACSHA512(key, 128);

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
            var expectedHash = ByteExtensions.HexToByteArray("80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");
            var hmac = new HMACSHA512(key);

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
            var expectedHash = ByteExtensions.HexToByteArray("e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58");
            var hmac = new HMACSHA512(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }
    }
}
