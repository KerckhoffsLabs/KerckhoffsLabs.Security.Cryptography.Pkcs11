using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for AesCcmPkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   AesCcmPkcs11Tests.cs            — this file: backend-free generic/argument tests (always run)
//   AesCcmPkcs11Tests.SoftHsm2.cs   — AesCcmPkcs11Tests_SoftHsm  (real SoftHSM token)

/// <summary>
/// Backend-free tests: argument validation and the static size descriptors, none of which
/// touch a token.
/// </summary>
public sealed class AesCcmPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new AesCcmPkcs11(key: null!));

    [Fact]
    public void NonceByteSizes_MirrorsBcl()
    {
        var actual = AesCcmPkcs11.NonceByteSizes;
        var expected = AesCcm.NonceByteSizes;
        Assert.Equal(expected.MinSize, actual.MinSize);
        Assert.Equal(expected.MaxSize, actual.MaxSize);
        Assert.Equal(expected.SkipSize, actual.SkipSize);
    }

    [Fact]
    public void TagByteSizes_MirrorsBcl()
    {
        var actual = AesCcmPkcs11.TagByteSizes;
        var expected = AesCcm.TagByteSizes;
        Assert.Equal(expected.MinSize, actual.MinSize);
        Assert.Equal(expected.MaxSize, actual.MaxSize);
        Assert.Equal(expected.SkipSize, actual.SkipSize);
    }
}
