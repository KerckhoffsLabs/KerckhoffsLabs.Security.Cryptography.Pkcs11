using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for ECDsaPkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   ECDsaPkcs11Tests.cs             — this file: backend-free generic/argument tests (always run)
//   ECDsaPkcs11Tests.Managed.cs     — ECDsaPkcs11Tests_Managed     (in-process BCL-backed fake)
//   ECDsaPkcs11Tests.SoftHsm2.cs    — ECDsaPkcs11Tests_SoftHsm     (real SoftHSM token)
//   ECDsaPkcs11Tests.OpenCryptoki.cs — ECDsaPkcs11Tests_OpenCryptoki (real opencryptoki token)
//   ECDsaPkcs11Tests.Nss.cs         — ECDsaPkcs11Tests_Nss         (real NSS softoken)

public sealed class ECDsaPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new ECDsaPkcs11(key: null!));
}
