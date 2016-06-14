using System.Text;

namespace SshNet.Security.Cryptography.Common.Tests
{
    public static class StringExtensions
    {
        public static string Repeat(string text, int count)
        {
            var sb = new StringBuilder();

            for (var i = 0; i < count; i++)
                sb.Append(text);

            return sb.ToString();
        }
    }
}
