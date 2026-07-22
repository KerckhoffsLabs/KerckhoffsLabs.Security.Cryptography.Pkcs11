using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for MLKemPkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   MLKemPkcs11Tests.cs             — this file: backend-free generic/argument tests (always run)
//   MLKemPkcs11Tests.Managed.cs     — MLKemPkcs11Tests_Managed    (in-process BCL-backed fake)
//   MLKemPkcs11Tests.SoftHsm2.cs    — MLKemPkcs11Tests_SoftHsm    (real SoftHSM token)
//   MLKemPkcs11Tests.OpenCryptoki.cs — MLKemPkcs11Tests_OpenCryptoki (real opencryptoki token)
//   MLKemPkcs11Tests.Nss.cs         — MLKemPkcs11Tests_Nss        (real NSS softoken)

public sealed class MLKemPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new MLKemPkcs11(key: null!));
}
