using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for MLDsaPkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   MLDsaPkcs11Tests.cs             — this file: backend-free generic/argument tests (always run)
//   MLDsaPkcs11Tests.Managed.cs     — MLDsaPkcs11Tests_Managed    (in-process BCL-backed fake)
//   MLDsaPkcs11Tests.SoftHsm2.cs    — MLDsaPkcs11Tests_SoftHsm    (real SoftHSM token)
//   MLDsaPkcs11Tests.OpenCryptoki.cs — MLDsaPkcs11Tests_OpenCryptoki (real opencryptoki token)
//   MLDsaPkcs11Tests.Nss.cs         — MLDsaPkcs11Tests_Nss        (real NSS softoken)

public sealed class MLDsaPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new MLDsaPkcs11(key: null!));
}
