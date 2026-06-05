using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for AesGcmPkcs11 are split by backend across sibling files (each a distinct class — they
// cannot share one partial type because the backends need different xUnit collection fixtures):
//   AesGcmPkcs11Tests.cs            — this file: backend-free generic/argument tests (always run)
//   AesGcmPkcs11Tests.SoftHsm2.cs   — AesGcmPkcs11Tests_SoftHsm  (real SoftHSM token)

/// <summary>
/// Backend-free tests: argument validation and the static size descriptors, none of which
/// touch a token.
/// </summary>
public sealed class AesGcmPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new AesGcmPkcs11(key: null!));

    [Fact]
    public void NonceByteSizes_MirrorsBcl()
    {
        var actual = AesGcmPkcs11.NonceByteSizes;
        var expected = AesGcm.NonceByteSizes;
        Assert.Equal(expected.MinSize, actual.MinSize);
        Assert.Equal(expected.MaxSize, actual.MaxSize);
        Assert.Equal(expected.SkipSize, actual.SkipSize);
    }

    [Fact]
    public void TagByteSizes_MirrorsBcl()
    {
        var actual = AesGcmPkcs11.TagByteSizes;
        var expected = AesGcm.TagByteSizes;
        Assert.Equal(expected.MinSize, actual.MinSize);
        Assert.Equal(expected.MaxSize, actual.MaxSize);
        Assert.Equal(expected.SkipSize, actual.SkipSize);
    }
}
