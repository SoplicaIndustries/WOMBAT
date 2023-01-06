using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;
using System.Text;
using WOMBAT.Models;

namespace WOMBAT.Tools
{
    public class EncodingTools
    {
        public static byte[] Hash(string input, string salt)
        {
            if (String.IsNullOrEmpty(input))
            {
                return new byte[0];
            }


            using (var sha = new System.Security.Cryptography.SHA256Managed())
            {

                byte[] textBytes = System.Text.Encoding.UTF8.GetBytes(input + salt);
                byte[] hashBytes = sha.ComputeHash(textBytes);



                return hashBytes;
            }
        }

        public static string Salt()
        {
            var random = new RNGCryptoServiceProvider();


            int max_length = 32;


            byte[] salt = new byte[max_length];


            random.GetNonZeroBytes(salt);
            return Convert.ToBase64String(salt);
        }

        public static LoginHeaderData DecodeLoginHeader(string authHeader)
        {
            string encodedUsernamePassword = authHeader.Substring("Basic ".Length).Trim();
            Encoding encoding = Encoding.GetEncoding("iso-8859-1");
            string mailPassword = encoding.GetString(Convert.FromBase64String(encodedUsernamePassword));
            int seperatorIndex = mailPassword.IndexOf(':');
            string mail = mailPassword.Substring(0, seperatorIndex);
            string pass = mailPassword.Substring(seperatorIndex + 1);

            return new LoginHeaderData { Mail = mail, Pass = pass };

        }

        public static string CleanHeaderJWT(string authHeader)
        {
            string jwtString = authHeader.Substring("Bearer ".Length).Trim();
            return jwtString;
        }

        public static string EncodeToken(string token)
        {
            var tokenbytes = Encoding.UTF8.GetBytes(token);
            return WebEncoders.Base64UrlEncode(tokenbytes);
        }

        public static string DecodeToken(string token)
        {
            var decodedToken = WebEncoders.Base64UrlDecode(token);
            return Encoding.UTF8.GetString(decodedToken);

        }

    }
}
