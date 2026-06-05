using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for MLDsaPkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   MLDsaPkcs11Tests.cs            — this file: backend-free generic/argument tests (always run)
//   MLDsaPkcs11Tests.SoftHsm2.cs   — MLDsaPkcs11Tests_SoftHsm  (real SoftHSM token)

public sealed class MLDsaPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new MLDsaPkcs11(key: null!));
}
