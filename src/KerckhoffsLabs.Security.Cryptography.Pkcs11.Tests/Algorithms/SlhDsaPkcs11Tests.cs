using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

#pragma warning disable SYSLIB5006 // SlhDsaPkcs11 wraps the experimental BCL SlhDsa and is itself [Experimental].

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for SlhDsaPkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   SlhDsaPkcs11Tests.cs            — this file: backend-free generic/argument tests (always run)
//   SlhDsaPkcs11Tests.SoftHsm2.cs   — SlhDsaPkcs11Tests_SoftHsm  (real SoftHSM token)

public sealed class SlhDsaPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new SlhDsaPkcs11(key: null!));
}
