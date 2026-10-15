using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_GCM_PARAMS"/>. A managed descriptor: it holds the IV and
/// AAD as managed arrays and is rebuilt into each call's own scope, so one instance may safely back
/// several mechanisms.
/// </summary>
public sealed class CkmAesGcmParams : MechanismParameters
{
    private readonly byte[] _ivBytes;
    private readonly byte[] _aadBytes;
    private readonly int _tagBits;

    /// <summary>
    /// Initializes the GCM parameters.
    /// </summary>
    /// <param name="iv">Initialization vector (typically 12 bytes / 96 bits).</param>
    /// <param name="aad">Additional authenticated data; pass <see langword="default"/> for none.</param>
    /// <param name="tagBits">Authentication tag length in bits; must be a multiple of 8 in [32, 128]. Use 128 unless you have a specific reason.
    /// SP 800-38D §5.2.1.2 approves 96, 104, 112, 120 and 128 bits for general use (64 and 32 only under its Appendix C
    /// conditions), so <c>CryptoPolicy.SecureOnly</c> and <c>CryptoPolicy.FipsOnly</c> refuse a tag under 96 bits.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="iv"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="tagBits"/> is not a multiple of 8 in [32, 128].</exception>
    public CkmAesGcmParams(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> aad, int tagBits)
    {
        if (iv.IsEmpty) throw new ArgumentException("IV must not be empty.", nameof(iv));
        if (tagBits < 32 || tagBits > 128 || (tagBits % 8) != 0)
            throw new ArgumentOutOfRangeException(nameof(tagBits), "Tag size must be a multiple of 8 in [32, 128] bits.");

        _ivBytes = iv.ToArray();
        _aadBytes = aad.IsEmpty ? [] : aad.ToArray();
        _tagBits = tagBits;
    }

    /// <summary>The tag length, in bits, for the crypto policies' tag-length check.</summary>
    internal int TagBits => _tagBits;

    /// <inheritdoc/>
    internal override Pkcs11ParameterBlock BuildMarshalable(MechanismParameterScope scope)
    {
        return scope.WriteParameter(new CK_GCM_PARAMS
        {
            Iv = scope.Write(_ivBytes),
            IvLen = (NativeCULong)_ivBytes.Length,
            // PKCS#11 v2.40 left this field ambiguous: its header has ulIvBits, its text did not, and
            // NSS before 3.52 followed the text with a five-field struct. Such a module reads this
            // six-field struct's ulIvBits as pAAD, so anything but 0 would be dereferenced. A module
            // bound through a v3.x interface implements the reconciled layout, where ulIvBits is the
            // IV length in bits: NSS 3.52 and later reject the call unless it equals ulIvLen * 8, and
            // SoftHSM, Kryoptic and OpenCryptoki accept that value. So the IV length in bits for a
            // v3.x module, and 0 for a v2.x one or when the call has no session to ask.
            IvBits = scope is SessionParameterScope session && session.Session.SendsGcmIvBits
                ? (NativeCULong)((ulong)_ivBytes.Length * 8)
                : (NativeCULong)0,
            AAD = scope.Write(_aadBytes),
            AADLen = (NativeCULong)_aadBytes.Length,
            TagBits = (NativeCULong)_tagBits,
        });
    }
}
