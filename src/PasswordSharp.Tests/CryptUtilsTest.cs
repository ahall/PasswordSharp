using System;
using NUnit.Framework;

namespace PasswordSharp.Tests
{
    [TestFixture]
    public class CryptUtilsTest
    {
        private string[] SplitHash(string hash)
        {
            return hash.Split(new char[] { '$' }, 3, StringSplitOptions.RemoveEmptyEntries);
        }

        [Test]
        public void Crypt_Md5()
        {
            Assert.AreEqual("$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1",
                            CryptUtils.Crypt("Hello world!", "$1$saltstring"));
        }

        [Test]
        public void Crypt_Sha256()
        {
            Assert.AreEqual("$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
                            CryptUtils.Crypt("Hello world!", "$5$saltstring"));

            Assert.AreEqual("$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1",
                            CryptUtils.Crypt("a very much longer text to encrypt.  This one even stretches over morethan one line.",
                                             "$5$rounds=1400$anotherlongsaltstring"));
        }

        [Test]
        public void Crypt_Sha512()
        {
            Assert.AreEqual("$6$88YzdOoo$L1eCUeaJ914gHjxGToexJOeUbTxV89yWuDPEWxeSmI7pJowq2HMaWWvCcISDTt1p51Ui9YhkKhCVy5EsMeEnu.",
                            CryptUtils.Crypt("temp123", "$6$88YzdOoo"));


            Assert.AreEqual("$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1",
                            CryptUtils.Crypt("a very much longer text to encrypt.  This one even stretches over morethan one line.",
                                             "$6$rounds=1400$anotherlongsaltstring"));
        }

        [Test]
        public void Crypt_And_MakeSalt()
        {
            string salt = CryptUtils.MakeSalt();
            string hash = CryptUtils.Crypt("temp321", salt);
            Assert.Greater(hash.Length, 106);
            Assert.True(salt.Contains("rounds="));
            Assert.That(hash.StartsWith(salt + "$"));

            Assert.AreEqual(3, SplitHash(hash).Length);
        }

        [Test]
        public void MakeSalt_ShaMd5()
        {
            var salt = CryptUtils.MakeSalt(CryptUtils.TypeMd5);
            Assert.That(salt.StartsWith("$1$"));
            Assert.GreaterOrEqual(salt.Length, 11);
            Assert.True(salt.Contains("rounds="));
        }

        [Test]
        public void MakeSalt_Sha256()
        {
            var salt = CryptUtils.MakeSalt(CryptUtils.TypeSha256);
            Assert.That(salt.StartsWith("$5$"));
            Assert.GreaterOrEqual(salt.Length, 19);
            Assert.True(salt.Contains("rounds="));
        }

        [Test]
        public void MakeSalt_Sha512()
        {
            var salt = CryptUtils.MakeSalt();
            Assert.That(salt.StartsWith("$6$"));
            Assert.GreaterOrEqual(salt.Length, 19);
            Assert.True(salt.Contains("rounds="));

            salt = CryptUtils.MakeSalt(CryptUtils.TypeSha512);
            Assert.GreaterOrEqual(salt.Length, 19);
            Assert.True(salt.Contains("rounds="));
        }

        [Test]
        public void Verify_InvalidHash()
        {
            Assert.Throws(typeof(ArgumentException), delegate {
                CryptUtils.Verify("a", "temp123");
            });

            Assert.Throws(typeof(ArgumentException), delegate {
                CryptUtils.Verify("$6$mysalt", "temp123");
            });

            Assert.Throws(typeof(ArgumentException), delegate {
                CryptUtils.Verify("$6$mysalt$", "temp123");
            });

            Assert.Throws(typeof(ArgumentException), delegate {
                // Unsupported algorithm
                CryptUtils.Verify("$3$mysalt$jiojoijoij", "temp123");
            });
        }

        [Test]
        public void Verify_Md5()
        {
            string hash = "$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1";

            Assert.False(CryptUtils.Verify(hash, "temp123"));
            Assert.True(CryptUtils.Verify(hash, "Hello world!"));
            Assert.False(CryptUtils.Verify(hash, ""));
            Assert.False(CryptUtils.Verify(hash, "Hello world"));
            Assert.False(CryptUtils.Verify(hash, "temp3210"));
        }

        [Test]
        public void Verify_Sha256()
        {
            string hash = "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5";

            Assert.False(CryptUtils.Verify(hash, "temp123"));
            Assert.True(CryptUtils.Verify(hash, "Hello world!"));
            Assert.False(CryptUtils.Verify(hash, ""));
            Assert.False(CryptUtils.Verify(hash, "Hello world"));
            Assert.False(CryptUtils.Verify(hash, "temp3210"));
        }

        [Test]
        public void Verify_Sha256_Rounds()
        {
            string hash = "$5$rounds=80000$0BKabwRh5zlhFvjJ$342hkYArrO6Zo9/qyWQx1ERtn5/ruHBSf0T94sKA6x.";
            Assert.True(CryptUtils.Verify(hash, "temp123"));
        }

        [Test]
        public void Verify_Sha512()
        {
            string hash = "$6$N6zh6Fn8qjR+NTcf$PYE99rK0x1UIlTle1/xKYmKuixfb2rFLLRBE1S3a9mc8dFHIvQTQPq6Tapcgen7ChhLZvUI9BKjSHKSgjh45p/";

            Assert.False(CryptUtils.Verify(hash, "temp123"));
            Assert.True(CryptUtils.Verify(hash, "temp321"));
            Assert.False(CryptUtils.Verify(hash, ""));
            Assert.False(CryptUtils.Verify(hash, "a"));
            Assert.False(CryptUtils.Verify(hash, "temp3210"));
        }

        [Test]
        public void Verify_Sha512_Rounds()
        {
            string hash = "$6$rounds=60000$ud68WwQFgvTVQ7Li$9Jf8JGdoSDbdqZ4tjvNof7MF5wjkVMUirbrrLLZLXaVoFzm3qY6KSfbW7sgK1CD6Mp1xpnGJjBK2dtocpeoet.";
            Assert.True(CryptUtils.Verify(hash, "temp123"));
        }
    }
}