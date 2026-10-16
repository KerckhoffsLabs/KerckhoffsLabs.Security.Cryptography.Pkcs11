using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for ECDiffieHellmanPkcs11 are split by backend across sibling files (each a distinct class —
// they cannot share one partial type because the backends need different xUnit collection fixtures):
//   ECDiffieHellmanPkcs11Tests.cs             — this file: backend-free generic/argument tests (always run)
//   ECDiffieHellmanPkcs11Tests.Managed.cs     — ECDiffieHellmanPkcs11Tests_Managed     (in-process BCL-backed fake)
//   ECDiffieHellmanPkcs11Tests.SoftHsm2.cs    — ECDiffieHellmanPkcs11Tests_SoftHsm     (real SoftHSM token)
//   ECDiffieHellmanPkcs11Tests.OpenCryptoki.cs — ECDiffieHellmanPkcs11Tests_OpenCryptoki (real opencryptoki token)
//   ECDiffieHellmanPkcs11Tests.Nss.cs         — ECDiffieHellmanPkcs11Tests_Nss         (real NSS softoken)

public sealed class ECDiffieHellmanPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new ECDiffieHellmanPkcs11(key: null!));
}
