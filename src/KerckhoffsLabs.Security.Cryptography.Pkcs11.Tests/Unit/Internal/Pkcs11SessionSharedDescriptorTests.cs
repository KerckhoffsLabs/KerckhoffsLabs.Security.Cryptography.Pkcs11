using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// The three dual-mechanism operations reject a single output-bearing descriptor driving both halves.
/// </summary>
/// <remarks>
/// <para>
/// Sharing a descriptor across mechanisms is legal — each marshals into its own block, so neither can
/// disturb the other. The exception is a descriptor the token <i>writes into</i>: both halves absorb
/// into the same managed buffer, so whichever runs last wins and the other result vanishes with no
/// error. That is a wrong answer rather than a crash, which is why it is refused up front instead of
/// documented.
/// </para>
/// <para>
/// The guard runs before any native call, so the fake below never needs to serve one; a test that
/// reaches the fake has failed to reject something it should have.
/// </para>
/// </remarks>
public sealed class Pkcs11SessionSharedDescriptorTests
{
    private const ulong SessionId = 42;

    private static Pkcs11Session NewSession() => new(new FakeLowLevelPkcs11Library(), SessionId);

    private static CkmGcmMessageParams OutputBearing() =>
        CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);

    /// <summary>Input-only: the token reads it and writes nothing back, so sharing stays legal.</summary>
    private static CkmAesGcmParams InputOnly() => new(new byte[12], [0xAA], tagBits: 128);

    private static readonly ObjectHandle Key = new(1);

    [Fact]
    public void DecryptVerify_OneOutputDescriptorForBothHalves_Throws()
    {
        using var session = NewSession();
        var shared = OutputBearing();
        var verify = new Mechanism(CKM.CKM_AES_GCM, shared);
        var decrypt = new Mechanism(CKM.CKM_AES_GCM, shared);

        var ex = Assert.Throws<ArgumentException>(() => session.DecryptVerify(
            verify, Key, decrypt, Key, new MemoryStream([1, 2, 3]), new MemoryStream(), [4, 5], out _));

        Assert.Equal("decryptionMechanism", ex.ParamName);
        Assert.Contains("silently discarded", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DigestEncrypt_OneOutputDescriptorForBothHalves_Throws()
    {
        using var session = NewSession();
        var shared = OutputBearing();
        var digest = new Mechanism(CKM.CKM_AES_GCM, shared);
        var encrypt = new Mechanism(CKM.CKM_AES_GCM, shared);

        var ex = Assert.Throws<ArgumentException>(() => session.DigestEncrypt(
            digest, encrypt, Key, new MemoryStream([1, 2, 3]), new MemoryStream()));

        Assert.Equal("encryptionMechanism", ex.ParamName);
    }

    [Fact]
    public void DecryptDigest_OneOutputDescriptorForBothHalves_Throws()
    {
        using var session = NewSession();
        var shared = OutputBearing();
        var digest = new Mechanism(CKM.CKM_AES_GCM, shared);
        var decrypt = new Mechanism(CKM.CKM_AES_GCM, shared);

        var ex = Assert.Throws<ArgumentException>(() => session.DecryptDigest(
            digest, decrypt, Key, new MemoryStream([1, 2, 3]), new MemoryStream()));

        Assert.Equal("decryptionMechanism", ex.ParamName);
    }

    /// <summary>
    /// The byte[] overloads funnel into the stream ones, so the guard has to cover them too — a check
    /// placed on only the inner method would still be reached, but one placed per-overload could miss
    /// these entirely.
    /// </summary>
    [Fact]
    public void ByteArrayOverloads_AreCoveredToo()
    {
        using var session = NewSession();
        var shared = OutputBearing();
        var a = new Mechanism(CKM.CKM_AES_GCM, shared);
        var b = new Mechanism(CKM.CKM_AES_GCM, shared);

        Assert.Throws<ArgumentException>(() => session.DigestEncrypt(a, b, Key, [1, 2, 3], out _, out _));
        Assert.Throws<ArgumentException>(() => session.DecryptDigest(a, b, Key, [1, 2, 3], out _, out _));
        Assert.Throws<ArgumentException>(() => session.DecryptVerify(a, Key, b, Key, [1, 2, 3], [4], out _, out _));
    }

    /// <summary>
    /// The guard must stay narrow. An input-only descriptor shared across both halves is safe and has
    /// to keep working, or this would undo the sharing that was deliberately made legal.
    /// </summary>
    [Fact]
    public void SharingAnInputOnlyDescriptor_IsStillAllowed()
    {
        using var session = NewSession();
        var shared = InputOnly();
        var digest = new Mechanism(CKM.CKM_AES_GCM, shared);
        var encrypt = new Mechanism(CKM.CKM_AES_GCM, shared);

        // Reaches the fake and fails there instead — the point is that it is not rejected as an
        // argument error before the operation starts.
        Exception? ex = Record.Exception(() => session.DigestEncrypt(
            digest, encrypt, Key, new MemoryStream([1, 2, 3]), new MemoryStream()));

        Assert.IsNotType<ArgumentException>(ex);
    }

    /// <summary>Two separate output-bearing descriptors are exactly what the guard asks for.</summary>
    [Fact]
    public void TwoDistinctOutputDescriptors_AreAllowed()
    {
        using var session = NewSession();
        var digest = new Mechanism(CKM.CKM_AES_GCM, OutputBearing());
        var encrypt = new Mechanism(CKM.CKM_AES_GCM, OutputBearing());

        Exception? ex = Record.Exception(() => session.DigestEncrypt(
            digest, encrypt, Key, new MemoryStream([1, 2, 3]), new MemoryStream()));

        Assert.IsNotType<ArgumentException>(ex);
    }

    /// <summary>A mechanism with no descriptor at all must not trip the reference comparison.</summary>
    [Fact]
    public void MechanismsWithoutParameters_AreAllowed()
    {
        using var session = NewSession();
        var digest = new Mechanism(CKM.CKM_SHA256);
        var encrypt = new Mechanism(CKM.CKM_AES_GCM);

        Exception? ex = Record.Exception(() => session.DigestEncrypt(
            digest, encrypt, Key, new MemoryStream([1, 2, 3]), new MemoryStream()));

        Assert.IsNotType<ArgumentException>(ex);
    }
}
