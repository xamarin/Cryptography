using System.Globalization;
using System.Text;

namespace SshNet.Security.Cryptography.Common.Tests
{
    public static class ByteExtensions
    {
        public static byte[] HexToByteArray(string hexString)
        {
            var bytes = new byte[hexString.Length / 2];

            for (var i = 0; i < hexString.Length; i += 2)
            {
                var s = hexString.Substring(i, 2);
                bytes[i / 2] = byte.Parse(s, NumberStyles.HexNumber, null);
            }

            return bytes;
        }

        public static string ToHex(byte[] bytes)
        {
            var builder = new StringBuilder(bytes.Length * 2);

            foreach (byte b in bytes)
            {
                builder.Append(b.ToString("X2"));
            }

            return builder.ToString();
        }

        public static byte[] Repeat(byte b, int count)
        {
            var value = new byte[count];

            for (var i = 0; i < count; i++)
            {
                value[i] = b;
            }

            return value;
        }
    }
}
