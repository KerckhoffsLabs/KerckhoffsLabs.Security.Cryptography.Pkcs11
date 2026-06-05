using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for AesPkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   AesPkcs11Tests.cs            — this file: backend-free generic/argument tests (always run)
//   AesPkcs11Tests.SoftHsm2.cs   — AesPkcs11Tests_SoftHsm  (real SoftHSM token)
//   AesPkcs11Tests.Managed.cs    — AesPkcs11Tests_Managed  (in-process managed ILowLevelPkcs11Library)
// (No .MockHsm.cs — pkcs11-mock returns canned data and cannot perform AES crypto.)

/// <summary>Backend-free argument tests for <see cref="AesPkcs11"/>.</summary>
public sealed class AesPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new AesPkcs11(key: null!));
}
