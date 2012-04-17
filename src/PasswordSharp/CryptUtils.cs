using System.Text;
using System;
using System.Security.Cryptography;

namespace PasswordSharp
{
    public class CryptUtils
    {
        public const string TypeMd5 = "$1$";
        public const string TypeSha256 = "$5$";
        public const string TypeSha512 = "$6$";

        public const string DefaultType = TypeSha512;

        public static string Crypt(string password, string salt)
        {
            var keyPtr = new ArrayPointer<byte>(Encoding.UTF8.GetBytes(password + "\0"));
            var saltPtr = new ArrayPointer<byte>(Encoding.UTF8.GetBytes(salt + "\0"));

            /* Try to find out whether we have to use MD5 encryption replacement.  */
            if (CryptImpl.strncmp(CryptImpl.md5_salt_prefix, saltPtr, CryptImpl.strlen(CryptImpl.md5_salt_prefix)) == 0)
            {
                return CryptImpl.CryptMd5(keyPtr, saltPtr);
            }

            /* Try to find out whether we have to use SHA256 encryption replacement.  */
            if (CryptImpl.strncmp(CryptImpl.sha256_salt_prefix, saltPtr, CryptImpl.strlen(CryptImpl.sha256_salt_prefix)) == 0)
            {
                return CryptImpl.CryptSha256(keyPtr, saltPtr);
            }

            /* Try to find out whether we have to use SHA512 encryption replacement.  */
            if (CryptImpl.strncmp(CryptImpl.sha512_salt_prefix, saltPtr, CryptImpl.strlen(CryptImpl.sha512_salt_prefix)) == 0)
            {
                return CryptImpl.CryptSha512(keyPtr, saltPtr);
            }

            throw new ArgumentException("Unsupported algorithm");
        }

        private static string[] SplitHash(string hash)
        {
            return hash.Split(new char[] { '$' }, 3, StringSplitOptions.RemoveEmptyEntries);
        }

        public static bool Verify(string hash, string password)
        {
            var components = SplitHash(hash);
            if (components.Length != 3)
            {
                throw new ArgumentException("Invalid hash");
            }

            string salt = string.Format("${0}${1}", components[0], components[1]);

            // Has the password with the salt from the hash
            string newHash = Crypt(password, salt);

            return hash == newHash;
        }

        public static string MakeSalt()
        {
            return MakeSalt(DefaultType);
        }

        public static string MakeSalt(string algoType)
        {
            int saltChars = 16;
            if (algoType == TypeMd5)
            {
                saltChars = 8;
            }

            // Find out how many random bytes we need for the saltChars as
            // base64 has overhead of 4/3
            double base64Overhead = 4.0 / 3.0;

            int bytesNeeded = (int)((double)saltChars / base64Overhead);

            byte[] randomBytes = new byte[bytesNeeded];

            var random = new RNGCryptoServiceProvider();
            random.GetNonZeroBytes(randomBytes);

            return algoType + Convert.ToBase64String(randomBytes);
        }
    }
}
