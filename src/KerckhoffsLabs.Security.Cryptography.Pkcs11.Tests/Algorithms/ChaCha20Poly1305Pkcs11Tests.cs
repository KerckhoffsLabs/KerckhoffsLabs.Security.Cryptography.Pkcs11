using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// Tests for ChaCha20Poly1305Pkcs11 are split by backend across sibling files (each a distinct class —
// they cannot share one partial type because the backends need different xUnit collection fixtures):
//   ChaCha20Poly1305Pkcs11Tests.cs            — this file: backend-free generic/argument tests (always run)
//   ChaCha20Poly1305Pkcs11Tests.SoftHsm2.cs   — ChaCha20Poly1305Pkcs11Tests_SoftHsm  (real SoftHSM token)

/// <summary>
/// Backend-free tests: ctor null-guard and the static size contracts. The BCL
/// <see cref="System.Security.Cryptography.ChaCha20Poly1305"/> does not expose nonce/tag
/// <c>KeySizes</c>, so the adapter defines them per RFC 8439 (12-byte nonce, 16-byte tag) and
/// these tests pin that contract.
/// </summary>
public sealed class ChaCha20Poly1305Pkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new ChaCha20Poly1305Pkcs11(key: null!));

    [Fact]
    public void NonceByteSizes_IsExactlyTwelve()
    {
        var ns = ChaCha20Poly1305Pkcs11.NonceByteSizes;
        Assert.Equal(12, ns.MinSize);
        Assert.Equal(12, ns.MaxSize);
        Assert.Equal(1, ns.SkipSize);
    }

    [Fact]
    public void TagByteSizes_IsExactlySixteen()
    {
        var ts = ChaCha20Poly1305Pkcs11.TagByteSizes;
        Assert.Equal(16, ts.MinSize);
        Assert.Equal(16, ts.MaxSize);
        Assert.Equal(1, ts.SkipSize);
    }
}
