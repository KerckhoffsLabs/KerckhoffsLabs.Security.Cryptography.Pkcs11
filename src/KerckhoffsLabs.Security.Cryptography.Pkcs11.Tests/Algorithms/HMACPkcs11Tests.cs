using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for HMACPkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   HMACPkcs11Tests.cs             — this file: backend-free generic/argument tests (always run)
//   HMACPkcs11Tests.Managed.cs     — HMACPkcs11Tests_Managed     (in-process BCL-backed fake)
//   HMACPkcs11Tests.SoftHsm2.cs    — HMACPkcs11Tests_SoftHsm     (real SoftHSM token)
//   HMACPkcs11Tests.OpenCryptoki.cs — HMACPkcs11Tests_OpenCryptoki (real opencryptoki token)
//   HMACPkcs11Tests.Nss.cs         — HMACPkcs11Tests_Nss         (real NSS softoken)

public sealed class HMACPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new HMACPkcs11(key: null!, HashAlgorithmName.SHA256));
}
