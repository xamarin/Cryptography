using System.Text;
using SshNet.Security.Cryptography.Common.Tests;
using Xunit;

namespace SshNet.Security.Cryptography.Tests
{
    /// <summary>
    /// Test cases are from http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf Appendix B
    /// </summary>
    public class SHA256Test
    {
        private readonly SHA256 _hashAlgorithm;

        public SHA256Test()
        {
            _hashAlgorithm = new SHA256();
        }

        [Fact]
        public void Fips180_1()
        {
            var data = Encoding.ASCII.GetBytes("abc");
            var expectedHash = ByteExtensions.HexToByteArray("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Fips180_2()
        {
            var data = Encoding.ASCII.GetBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
            var expectedHash = ByteExtensions.HexToByteArray("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Fips180_3()
        {
            var data = Encoding.ASCII.GetBytes(new string('a', 1000000));
            var expectedHash = ByteExtensions.HexToByteArray("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }
    }
}
