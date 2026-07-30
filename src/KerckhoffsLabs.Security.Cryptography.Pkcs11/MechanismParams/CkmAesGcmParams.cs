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
    /// <param name="aad">Additional authenticated data; pass <c>default</c> for none.</param>
    /// <param name="tagBits">Authentication tag length in bits; must be a multiple of 8 in [32, 128]. Use 128 unless you have a specific reason.</param>
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

    /// <inheritdoc/>
    internal override object BuildMarshalable(MechanismParameterScope scope)
    {
        return new CK_GCM_PARAMS
        {
            Iv = scope.Write(_ivBytes),
            IvLen = (NativeCULong)_ivBytes.Length,
            // Legacy field; PKCS#11 v3.2 §2.5.13 allows 0 and the IV length is taken from IvLen.
            // Some tokens reject a non-zero value (SoftHSM's AES-GCM KAT fails when it is set), so
            // leave it 0 for maximum interoperability. NSS softoken's classic C_EncryptInit GCM path
            // conversely rejects 0, so GCM against NSS goes through the message-based AesGcmPkcs11
            // façade (C_MessageEncrypt), not this classic-params path.
            IvBits = (NativeCULong)0,
            AAD = scope.Write(_aadBytes),
            AADLen = (NativeCULong)_aadBytes.Length,
            TagBits = (NativeCULong)_tagBits,
        };
    }
}
