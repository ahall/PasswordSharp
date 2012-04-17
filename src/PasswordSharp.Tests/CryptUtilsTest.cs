using System;
using NUnit.Framework;

namespace PasswordSharp.Tests
{
    [TestFixture]
    public class CryptUtilsTest
    {
        [Test]
        public void Md5()
        {
            Assert.AreEqual("$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1",
                            CryptUtils.Crypt("Hello world!", "$1$saltstring"));
        }

        [Test]
        public void Sha256()
        {
            Assert.AreEqual("$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
                            CryptUtils.Crypt("Hello world!", "$5$saltstring"));

            Assert.AreEqual("$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1",
                            CryptUtils.Crypt("a very much longer text to encrypt.  This one even stretches over morethan one line.",
                                             "$5$rounds=1400$anotherlongsaltstring"));
        }

        [Test]
        public void Sha512()
        {
            Assert.AreEqual("$6$88YzdOoo$L1eCUeaJ914gHjxGToexJOeUbTxV89yWuDPEWxeSmI7pJowq2HMaWWvCcISDTt1p51Ui9YhkKhCVy5EsMeEnu.",
                            CryptUtils.Crypt("temp123", "$6$88YzdOoo"));


            Assert.AreEqual("$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1",
                            CryptUtils.Crypt("a very much longer text to encrypt.  This one even stretches over morethan one line.",
                                             "$6$rounds=1400$anotherlongsaltstring"));
        }
    }
}

