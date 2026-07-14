using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for DESPkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   DESPkcs11Tests.cs            — this file: backend-free generic/argument tests (always run)
//   DESPkcs11Tests.SoftHsm2.cs   — DESPkcs11Tests_SoftHsm  (real SoftHSM token)

// DESPkcs11 is [Obsolete] (single DES has a 56-bit key); the secure-defaults gate is the point of
// the type, so KLPKCS11003 is suppressed deliberately at the use sites.
#pragma warning disable KLPKCS11003

/// <summary>Backend-free argument tests for <see cref="DESPkcs11"/>.</summary>
public sealed class DESPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new DESPkcs11(key: null!));
}
