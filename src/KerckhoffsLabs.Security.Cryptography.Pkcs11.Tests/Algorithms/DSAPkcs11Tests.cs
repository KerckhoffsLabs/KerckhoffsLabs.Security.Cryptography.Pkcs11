using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for DSAPkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   DSAPkcs11Tests.cs            — this file: backend-free generic/argument tests (always run)
//   DSAPkcs11Tests.SoftHsm2.cs   — DSAPkcs11Tests_SoftHsm  (real SoftHSM token)

public sealed class DSAPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new DSAPkcs11(key: null!));
}
