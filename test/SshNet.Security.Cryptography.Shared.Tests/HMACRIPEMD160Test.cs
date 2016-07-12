using System.Text;
using SshNet.Security.Cryptography.Common.Tests;
using Xunit;

namespace SshNet.Security.Cryptography.Tests
{
    /// <summary>
    /// Test cases are from https://tools.ietf.org/html/rfc2286.
    /// </summary>
    public class HMACRIPEMD160Test
    {
        [Fact]
        public void Rfc2286_1()
        {
            var key = ByteExtensions.Repeat(0x0b, 20);
            var data = ByteExtensions.HexToByteArray("4869205468657265"); // "Hi There"
            var expectedHash = ByteExtensions.HexToByteArray("24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668");
            var hmac = new HMACRIPEMD160(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc2286_2()
        {
            var key = ByteExtensions.HexToByteArray("4a656665"); // "Jefe";
            var data = ByteExtensions.HexToByteArray("7768617420646f2079612077616e7420666f72206e6f7468696e673f"); // "what do ya want for nothing?"
            var expectedHash = ByteExtensions.HexToByteArray("dda6c0213a485a9e24f4742064a7f033b43c4069");
            var hmac = new HMACRIPEMD160(key);

            var actualHash = hmac.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }
    }
}
