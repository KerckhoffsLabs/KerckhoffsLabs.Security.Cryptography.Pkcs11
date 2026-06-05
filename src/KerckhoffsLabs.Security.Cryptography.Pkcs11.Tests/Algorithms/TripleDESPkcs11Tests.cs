using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for TripleDESPkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   TripleDESPkcs11Tests.cs            — this file: backend-free generic/argument tests (always run)
//   TripleDESPkcs11Tests.SoftHsm2.cs   — TripleDESPkcs11Tests_SoftHsm  (real SoftHSM token)

// TripleDESPkcs11 is [Obsolete] (64-bit block / Sweet32, NIST-deprecated); the secure-defaults gate
// is the point of the type, so CS0618 is suppressed deliberately at the use sites.
#pragma warning disable CS0618

/// <summary>Backend-free argument tests for <see cref="TripleDESPkcs11"/>.</summary>
public sealed class TripleDESPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new TripleDESPkcs11(key: null!));
}
