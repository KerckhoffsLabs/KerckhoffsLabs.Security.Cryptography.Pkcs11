using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for SP800108HmacCounterKdfPkcs11 are split by backend across sibling files (each a distinct
// class — they cannot share one partial type because the backends need different xUnit collection
// fixtures):
//   SP800108HmacCounterKdfPkcs11Tests.cs            — this file: backend-free generic/argument tests (always run)
//   SP800108HmacCounterKdfPkcs11Tests.SoftHsm2.cs   — SP800108HmacCounterKdfPkcs11Tests_SoftHsm  (real SoftHSM token)

/// <summary>Backend-free argument tests for <see cref="SP800108HmacCounterKdfPkcs11"/>.</summary>
public sealed class SP800108HmacCounterKdfPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(
            () => new SP800108HmacCounterKdfPkcs11(key: null!, HashAlgorithmName.SHA256));
}
