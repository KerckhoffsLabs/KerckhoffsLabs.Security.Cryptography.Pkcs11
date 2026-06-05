using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for ECDsaPkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   ECDsaPkcs11Tests.cs            — this file: backend-free generic/argument tests (always run)
//   ECDsaPkcs11Tests.SoftHsm2.cs   — ECDsaPkcs11Tests_SoftHsm  (real SoftHSM token)

public sealed class ECDsaPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new ECDsaPkcs11(key: null!));
}
