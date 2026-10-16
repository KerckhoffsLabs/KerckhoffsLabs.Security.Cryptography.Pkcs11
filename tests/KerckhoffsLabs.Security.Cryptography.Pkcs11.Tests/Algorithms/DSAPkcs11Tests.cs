using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

// DSAPkcs11 is intentionally [Obsolete] (DSA is disallowed by FIPS 186-5); exercising it here is deliberate.
#pragma warning disable KLPKCS11006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for DSAPkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   DSAPkcs11Tests.cs             — this file: backend-free generic/argument tests (always run)
//   DSAPkcs11Tests.Managed.cs     — DSAPkcs11Tests_Managed     (in-process BCL-backed fake)
//   DSAPkcs11Tests.SoftHsm2.cs    — DSAPkcs11Tests_SoftHsm     (real SoftHSM token)
//   DSAPkcs11Tests.OpenCryptoki.cs — DSAPkcs11Tests_OpenCryptoki (real opencryptoki token)
//   DSAPkcs11Tests.Nss.cs         — DSAPkcs11Tests_Nss         (real NSS softoken)

public sealed class DSAPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new DSAPkcs11(key: null!));
}
