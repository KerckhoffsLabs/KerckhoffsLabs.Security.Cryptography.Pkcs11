using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for SHA512Pkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   SHA512Pkcs11Tests.cs            — this file: backend-free generic/argument tests (always run)
//   SHA512Pkcs11Tests.SoftHsm2.cs   — SHA512Pkcs11Tests_SoftHsm  (real SoftHSM token)

/// <summary>Backend-free argument tests for <see cref="SHA512Pkcs11"/>.</summary>
public sealed class SHA512Pkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullWorkspace_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new SHA512Pkcs11(workspace: null!));
}
