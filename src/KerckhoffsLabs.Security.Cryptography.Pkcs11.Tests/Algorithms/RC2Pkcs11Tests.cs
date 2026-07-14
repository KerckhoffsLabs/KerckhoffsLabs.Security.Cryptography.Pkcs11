using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for RC2Pkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   RC2Pkcs11Tests.cs            — this file: backend-free generic/argument tests (always run)
//   RC2Pkcs11Tests.SoftHsm2.cs   — RC2Pkcs11Tests_SoftHsm  (real SoftHSM token)

// RC2Pkcs11 is [Obsolete] (weak legacy cipher); the secure-defaults gate is the point of the type,
// so KLPKCS11005 is suppressed deliberately at the use sites.
#pragma warning disable KLPKCS11005

/// <summary>Backend-free argument tests for <see cref="RC2Pkcs11"/>.</summary>
public sealed class RC2Pkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new RC2Pkcs11(key: null!));
}
