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
            var data = ByteExtensions.HexToByteArray("616263"); // "abc"
            var expectedHash = ByteExtensions.HexToByteArray("A9993E364706816ABA3E25717850C26C9CD0D89D");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc3174_2()
        {
            var data = ByteExtensions.HexToByteArray("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071"); // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            var expectedHash = ByteExtensions.HexToByteArray("84983E441C3BD26EBAAE4AA1F95129E5E54670F1");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc3174_3()
        {
            var data = ByteExtensions.HexToByteArray(StringExtensions.Repeat("61", 1000000)); // "a" * 1000000
            var expectedHash = ByteExtensions.HexToByteArray("34AA973CD4C4DAA4F61EEB2BDBAD27316534016F");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void Rfc3174_4()
        {
            var data = ByteExtensions.HexToByteArray(StringExtensions.Repeat("3031323334353637", 8 * 10)); // "01234567" * (8*10)
            var expectedHash = ByteExtensions.HexToByteArray("DEA356A2CDDD90C7A7ECEDC5EBB563934F460452");

            var actualHash = _hashAlgorithm.ComputeHash(data);

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void TransformFinalBlock_InputCountLessThanBlockSize()
        {
            var data1 = new byte[] { 10, 13, 25, 14, 26 };
            var expectedHash1 = new byte[] { 21, 29, 28, 205, 37, 37, 222, 131, 237, 85, 37, 15, 19, 41, 248, 160, 238, 30, 84, 188 };
            var actual1 = _hashAlgorithm.TransformFinalBlock(data1, 1, 2);
            Assert.Equal(new byte[] { 13, 25 }, actual1);
            Assert.Equal(expectedHash1, _hashAlgorithm.Hash);

            var data2 = new byte[] { 36, 12, 15 };
            var expectedHash2 = new byte[] { 171, 192, 206, 160, 133, 70, 186, 240, 35, 157, 214, 104, 52, 219, 37, 207, 142, 157, 1, 70 };
            var actual2 = _hashAlgorithm.TransformFinalBlock(data2, 0, data2.Length);
            Assert.Equal(data2, actual2);
            Assert.NotSame(data2, actual2);
            Assert.Equal(expectedHash2, _hashAlgorithm.Hash);

            var data3 = new byte[] { 11, 13, 17 };
            var expectedHash3 = new byte[] { 50, 153, 154, 43, 196, 241, 137, 156, 89, 132, 42, 76, 212, 235, 118, 69, 10, 171, 229, 210 };
            var actual3 = _hashAlgorithm.ComputeHash(data3);

            Assert.Equal(expectedHash3, actual3);
            Assert.Equal(expectedHash3, _hashAlgorithm.Hash);
            Assert.NotSame(expectedHash3, _hashAlgorithm.Hash);
        }

        [Fact]
        public void TransformBlock_TotalBytesLessThanBlockSize()
        {
            var data = new byte[] { 10, 13, 25, 14, 26, 5, 7, 9, 1, 12, 11, 54, 13, 54, 15, 17, 87, 16, 92, 20, 21, 25, 65, 78, 65, 43, 12, 53, 79, 80, 1, 32, 34, 56, 43, 6, 1, 56, 1, 12, 11, 54, 13, 54, 15, 17, 87, 16, 92, 20, 21, 25, 65, 78, 65, 43, 12, 53, 79, 1, 12, 11, 54, 13, 54, 15, 17, 87, 16, 92, 20, 21, 25, 65, 78, 65, 43, 12, 53, 79, 5 };
            var expectedHash = new byte[] { 12, 42, 118, 169, 170, 59, 51, 191, 192, 157, 90, 187, 16, 54, 239, 42, 84, 200, 76, 50 };
            var outputBuffer = new byte[100];

            var actual1 = _hashAlgorithm.TransformBlock(data, 0, 50, outputBuffer, 0);
            Assert.Equal(50, actual1);
            var actual2 = _hashAlgorithm.TransformBlock(data, 50, 13, outputBuffer, 0);
            Assert.Equal(13, actual2);
            var actual3 = _hashAlgorithm.TransformFinalBlock(new byte[0], 0, 0);
            Assert.Equal(0, actual3.Length);
            Assert.Equal(expectedHash, _hashAlgorithm.Hash);
        }

        [Fact]
        public void TransformBlock_TotalBytesGreaterThanBlockSize()
        {
            var data = new byte[] { 10, 13, 25, 14, 26, 5, 7, 9, 1, 12, 11, 54, 13, 54, 15, 17, 87, 16, 92, 20, 21, 25, 65, 78, 65, 43, 12, 53, 79, 80, 1, 32, 34, 56, 43, 6, 1, 56, 1, 12, 11, 54, 13, 54, 15, 17, 87, 16, 92, 20, 21, 25, 65, 78, 65, 43, 12, 53, 79, 1, 12, 11, 54, 13, 54, 15, 17, 87, 16, 92, 20, 21, 25, 65, 78, 65, 43, 12, 53, 79, 5 };
            var expectedHash = new byte[] { 128, 163, 23, 117, 156, 106, 169, 171, 211, 31, 95, 85, 66, 31, 232, 41, 115, 58, 148, 22 };
            var outputBuffer = new byte[100];

            var actual1 = _hashAlgorithm.TransformBlock(data, 0, 75, outputBuffer, 0);
            Assert.Equal(75, actual1);
            var actual2 = _hashAlgorithm.TransformBlock(data, 75, 6, outputBuffer, 0);
            Assert.Equal(6, actual2);
            var actual3 = _hashAlgorithm.TransformFinalBlock(new byte[0], 0, 0);
            Assert.Equal(0, actual3.Length);
            Assert.Equal(expectedHash, _hashAlgorithm.Hash);
        }

        [Fact]
        public void TransformBlock_TotalBytesEqualsBlockSize()
        {
            var data = new byte[] { 10, 13, 25, 14, 26, 5, 7, 9, 1, 12, 11, 54, 13, 54, 15, 17, 87, 16, 92, 20, 21, 25, 65, 78, 65, 43, 12, 53, 79, 80, 1, 32, 34, 56, 43, 6, 1, 56, 1, 12, 11, 54, 13, 54, 15, 17, 87, 16, 92, 20, 21, 25, 65, 78, 41, 55, 32, 55, 12, 78, 2, 34, 53, 5, 22 };
            var expectedHash = new byte[] {40, 34, 15, 107, 222, 157, 191, 149, 93, 148, 21, 72, 215, 181, 74, 218, 157, 23, 121, 208};
            var outputBuffer = new byte[100];

            var actual1 = _hashAlgorithm.TransformBlock(data, 0, 60, outputBuffer, 0);
            Assert.Equal(60, actual1);
            var actual2 = _hashAlgorithm.TransformBlock(data, 60, 4, outputBuffer, 0);
            Assert.Equal(4, actual2);
            var actual3 = _hashAlgorithm.TransformFinalBlock(new byte[0], 0, 0);
            Assert.Equal(0, actual3.Length);
            Assert.Equal(expectedHash, _hashAlgorithm.Hash);
        }

        [Fact]
        public void TransformBlockAndTransformFinalBlock()
        {
            var data = new byte[] { 10, 13, 25, 14, 26, 5, 7, 9, 1, 12, 11, 54, 13, 54, 15, 17, 87, 16, 92, 20, 21, 25, 65, 78, 65, 43, 12, 53, 79, 80, 1, 32, 34, 56, 43, 6, 1, 56, 1, 12, 11, 54, 13, 54, 15, 17, 87, 16, 92, 20, 21, 25, 65, 78, 65, 43, 12, 53, 79, 1, 12, 11, 54, 13, 54, 15, 17, 87, 16, 92, 20, 21, 25, 65, 78, 65, 43, 12, 53, 79, 5 };
            var expectedHash = new byte[] { 128, 163, 23, 117, 156, 106, 169, 171, 211, 31, 95, 85, 66, 31, 232, 41, 115, 58, 148, 22 };
            var outputBuffer = new byte[100];

            var actual1 = _hashAlgorithm.TransformBlock(data, 0, 70, outputBuffer, 0);
            Assert.Equal(70, actual1);
            Assert.Equal(ByteExtensions.Take(data, 0, 70), ByteExtensions.Take(outputBuffer, 0, 70));
            Assert.Equal(ByteExtensions.Repeat(0, 30), ByteExtensions.Take(outputBuffer, 70, 30));
            var actual2 = _hashAlgorithm.TransformBlock(data, 70, 6, outputBuffer, 15);
            Assert.Equal(6, actual2);
            Assert.Equal(ByteExtensions.Take(data, 0, 15), ByteExtensions.Take(outputBuffer, 0, 15));
            Assert.Equal(ByteExtensions.Take(data, 70, 6), ByteExtensions.Take(outputBuffer, 15, 6));
            Assert.Equal(ByteExtensions.Take(data, 21, 49), ByteExtensions.Take(outputBuffer, 21, 49));
            Assert.Equal(ByteExtensions.Repeat(0, 30), ByteExtensions.Take(outputBuffer, 70, 30));
            var actual3 = _hashAlgorithm.TransformFinalBlock(data, 76, 5);
            Assert.Equal(ByteExtensions.Take(data, 76, 5), actual3);
            Assert.Equal(expectedHash, _hashAlgorithm.Hash);
        }

        [Fact]
        public void TransformFinalBlockShouldAddBlockWhenThereIsNoRoomForMessageLength()
        {
            var data = new byte[] { 10, 13, 25, 14, 26, 5, 7, 9, 1, 12, 11, 54, 13, 54, 15, 17, 87, 16, 92, 20, 21, 25, 65, 78, 65, 43, 12, 53, 79, 80, 1, 32, 34, 56, 43, 6, 1, 56, 1, 12, 11, 54, 13, 54, 15, 17, 87, 16, 92, 20, 21, 25, 65, 78, 65, 43, 12, 53, 79, 1, 12, 11, 54, 13, 54, 15, 17, 87, 16, 92, 20, 21, 25, 65, 78, 65, 43, 12, 53, 79, 5, 14, 26, 5, 7, 9, 1, 12, 11, 54, 13, 54, 15, 17, 87, 16, 92, 20, 21, 25, 65, 78, 65, 43, 12, 53, 79, 80, 1, 32, 34, 56, 43, 6, 1, 56, 1, 12, 11, 54, 13, 54, 15 };
            var expectedHash = new byte[] { 130, 147, 240, 106, 140, 1, 186, 57, 153, 120, 4, 32, 80, 250, 92, 93, 235, 206, 199, 62 };

            var actual = _hashAlgorithm.TransformFinalBlock(data, 0, data.Length);
            Assert.Equal(data, actual);
            Assert.Equal(expectedHash, _hashAlgorithm.Hash);
        }
    }
}
