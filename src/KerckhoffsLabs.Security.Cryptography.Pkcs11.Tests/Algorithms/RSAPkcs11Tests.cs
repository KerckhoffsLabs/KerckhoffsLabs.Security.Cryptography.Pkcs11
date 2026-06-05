using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for RSAPkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   RSAPkcs11Tests.cs            — this file: backend-free generic/argument tests (always run)
//   RSAPkcs11Tests.SoftHsm2.cs   — RSAPkcs11Tests_SoftHsm  (real SoftHSM token)

public sealed class RSAPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new RSAPkcs11(key: null!));
    }
}
