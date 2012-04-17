using System.Text;
using System;

namespace PasswordSharp
{
    public class CryptUtils
    {
        public static string Crypt(string key, string salt)
        {
            var keyPtr = new ArrayPointer<byte>(Encoding.UTF8.GetBytes(key + "\0"));

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

    }
}
