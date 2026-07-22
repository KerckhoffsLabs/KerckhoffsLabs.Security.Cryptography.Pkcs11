using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for SHA3_384Pkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   SHA3_384Pkcs11Tests.cs             — this file: backend-free generic/argument tests (always run)
//   SHA3_384Pkcs11Tests.Managed.cs     — SHA3_384Pkcs11Tests_Managed     (in-process BCL-backed fake)
//   SHA3_384Pkcs11Tests.SoftHsm2.cs    — SHA3_384Pkcs11Tests_SoftHsm     (real SoftHSM token)
//   SHA3_384Pkcs11Tests.OpenCryptoki.cs — SHA3_384Pkcs11Tests_OpenCryptoki (real opencryptoki token)

/// <summary>Backend-free argument tests for <see cref="SHA3_384Pkcs11"/>.</summary>
public sealed class SHA3_384Pkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullWorkspace_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new SHA3_384Pkcs11(workspace: null!));
}
