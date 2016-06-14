using System.Text;
using SshNet.Security.Cryptography.Common.Tests;
using Xunit;

namespace SshNet.Security.Cryptography.Tests
{
    /// <summary>
    /// Test cases are from http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf Appendix A
    /// </summary>
    public class SHA1Test
    {
        private readonly SHA1 _hashAlgorithm;

        public SHA1Test()
        {
            _hashAlgorithm = new SHA1();
        }

        [Fact]
        public void Rfc3174_1()
        {
            var data = Encoding.ASCII.GetBytes("abc");
            var expectedHash = ByteExtensions.HexToByteArray("A9993E364706816ABA3E25717850C26C9CD0D89D");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc3174_2()
        {
            var data = Encoding.ASCII.GetBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
            var expectedHash = ByteExtensions.HexToByteArray("84983E441C3BD26EBAAE4AA1F95129E5E54670F1");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc3174_3()
        {
            var data = Encoding.ASCII.GetBytes(new string('a', 1000000));
            var expectedHash = ByteExtensions.HexToByteArray("34AA973CD4C4DAA4F61EEB2BDBAD27316534016F");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc3174_4()
        {
            var data = Encoding.ASCII.GetBytes(StringExtensions.Repeat("0123456701234567012345670123456701234567012345670123456701234567", 10));
            var expectedHash = ByteExtensions.HexToByteArray("DEA356A2CDDD90C7A7ECEDC5EBB563934F460452");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }
    }
}
