using System.Text;
using Renci.Common.Tests;
using Renci.Security.Cryptography;
using Xunit;

namespace Renci.SshNet.Tests.Classes.Security.Cryptography
{
    /// <summary>
    /// Test cases are from http://homes.esat.kuleuven.be/~bosselae/ripemd160.html.
    ///</summary>
    public class RIPEMD160Test
    {
        private readonly RIPEMD160 _hashAlgorithm;

        public RIPEMD160Test()
        {
            _hashAlgorithm = new RIPEMD160();
        }

        [Fact]
        public void test_1()
        {
            var data = Encoding.ASCII.GetBytes("");
            var expectedHash = ByteExtensions.HexToByteArray("9c1185a5c5e9fc54612808977ee8f548b2258d31");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void test_2()
        {
            var data = Encoding.ASCII.GetBytes("a");
            var expectedHash = ByteExtensions.HexToByteArray("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void test_3()
        {
            var data = Encoding.ASCII.GetBytes("abc");
            var expectedHash = ByteExtensions.HexToByteArray("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void test_4()
        {
            var data = Encoding.ASCII.GetBytes("message digest");
            var expectedHash = ByteExtensions.HexToByteArray("5d0689ef49d2fae572b881b123a85ffa21595f36");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void test_5()
        {
            var data = Encoding.ASCII.GetBytes("abcdefghijklmnopqrstuvwxyz");
            var expectedHash = ByteExtensions.HexToByteArray("f71c27109c692c1b56bbdceb5b9d2865b3708dbc");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void test_6()
        {
            var data = Encoding.ASCII.GetBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
            var expectedHash = ByteExtensions.HexToByteArray("12a053384a9c0c88e405a06c27dcf49ada62eb2b");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void test_7()
        {
            var data = Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
            var expectedHash = ByteExtensions.HexToByteArray("b0e20b6e3116640286ed3a87a5713079b21f5189");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void test_8()
        {
            var data = Encoding.ASCII.GetBytes(StringExtensions.Repeat("1234567890", 8));
            var expectedHash = ByteExtensions.HexToByteArray("9b752e45573d4b39f4dbd3323cab82bf63326bfb");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void test_9()
        {
            var data = Encoding.ASCII.GetBytes(new string('a', 1000000));
            var expectedHash = ByteExtensions.HexToByteArray("52783243c1697bdbe16d37f97f68f08325dc1528");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }
    }
}
