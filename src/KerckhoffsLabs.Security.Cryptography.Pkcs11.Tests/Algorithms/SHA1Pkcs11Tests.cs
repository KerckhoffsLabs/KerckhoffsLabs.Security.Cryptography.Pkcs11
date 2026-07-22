using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for SHA1Pkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   SHA1Pkcs11Tests.cs             — this file: backend-free generic/argument tests (always run)
//   SHA1Pkcs11Tests.Managed.cs     — SHA1Pkcs11Tests_Managed     (in-process BCL-backed fake)
//   SHA1Pkcs11Tests.SoftHsm2.cs    — SHA1Pkcs11Tests_SoftHsm     (real SoftHSM token)
//   SHA1Pkcs11Tests.OpenCryptoki.cs — SHA1Pkcs11Tests_OpenCryptoki (real opencryptoki token)

// SHA1Pkcs11 is [Obsolete] (broken crypto); the gate is the point of the type, so KLPKCS11002 is
// suppressed deliberately at the use sites.
#pragma warning disable KLPKCS11002

/// <summary>Backend-free argument tests for <see cref="SHA1Pkcs11"/>.</summary>
public sealed class SHA1Pkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullWorkspace_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new SHA1Pkcs11(workspace: null!));
}
#pragma warning restore KLPKCS11002
