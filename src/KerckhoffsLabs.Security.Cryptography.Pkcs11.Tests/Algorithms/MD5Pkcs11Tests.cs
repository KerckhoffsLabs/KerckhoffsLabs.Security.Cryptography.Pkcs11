using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for MD5Pkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   MD5Pkcs11Tests.cs             — this file: backend-free generic/argument tests (always run)
//   MD5Pkcs11Tests.Managed.cs     — MD5Pkcs11Tests_Managed     (in-process BCL-backed fake)
//   MD5Pkcs11Tests.SoftHsm2.cs    — MD5Pkcs11Tests_SoftHsm     (real SoftHSM token)
//   MD5Pkcs11Tests.OpenCryptoki.cs — MD5Pkcs11Tests_OpenCryptoki (real opencryptoki token)

// MD5Pkcs11 is [Obsolete] (broken crypto); the gate is the point of the type, so KLPKCS11001 is
// suppressed deliberately at the use sites.
#pragma warning disable KLPKCS11001

/// <summary>Backend-free argument tests for <see cref="MD5Pkcs11"/>.</summary>
public sealed class MD5Pkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullWorkspace_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new MD5Pkcs11(workspace: null!));
}
#pragma warning restore KLPKCS11001
