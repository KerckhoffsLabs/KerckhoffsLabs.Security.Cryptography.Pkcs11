using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

// This file builds the very mechanisms the secure-by-default policy gates: it sits on the
// enforcement side of the check (Pkcs11Session.GuardMechanism rejects them at the point of use
// unless AllowInsecure is set), whereas KLPKCS11009 exists to warn a *caller* who selects one.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned <see cref="RC2"/> implementation backed by a PKCS#11 token's RC2 block-cipher
/// mechanisms (<c>CKM_RC2_CBC</c> / <c>CKM_RC2_CBC_PAD</c> / <c>CKM_RC2_ECB</c>). The key never enters
/// managed memory — this wraps a token-resident <see cref="Pkcs11Key"/> and does NOT take ownership.
/// </summary>
/// <remarks>
/// <para>
/// RC2 (RFC 2268) is a weak legacy 64-bit block cipher with a variable, often-reduced effective key
/// length; it is provided only for legacy/interop. Every operation throws
/// <c>InsecureOperationException</c> unless <see cref="Pkcs11Workspace.AllowInsecure"/> is set on the
/// wrapped key's workspace, and there is no authenticated RC2 mode to fall back to. Prefer
/// <see cref="AesGcmPkcs11"/> or <see cref="AesCcmPkcs11"/>.
/// </para>
/// <para>
/// Unlike AES/DES, the RC2 mechanisms carry an <b>effective-key-bits</b> parameter (RFC 2268). It is
/// taken from <see cref="RC2.EffectiveKeySize"/> (which defaults to <see cref="SymmetricAlgorithm.KeySize"/>);
/// set it before encrypting if the token key was created with a specific effective length. For CBC the
/// effective bits and IV travel together in <c>CK_RC2_CBC_PARAMS</c>; for ECB the effective bits travel
/// in <c>CK_RC2_PARAMS</c>.
/// </para>
/// <para>
/// Supported modes (on the token, once AllowInsecure is set):
/// <list type="bullet">
/// <item>CBC — PKCS7 (→ <c>CKM_RC2_CBC_PAD</c>) or None (→ <c>CKM_RC2_CBC</c>, block-aligned input).</item>
/// <item>ECB — None (→ <c>CKM_RC2_ECB</c>).</item>
/// </list>
/// Empty input that yields empty output is a no-op returned without touching the token; empty plaintext
/// with PKCS7 must emit a padding block, so it is sent to the token.
/// </para>
/// <para>
/// NOT supported: CFB/OFB (PKCS#11 defines no RC2 stream mode), <see cref="CreateEncryptor(byte[], byte[])"/> /
/// <see cref="CreateDecryptor(byte[], byte[])"/>, <see cref="GenerateKey"/>, the <see cref="Key"/>
/// property, and any padding other than PKCS7/None. These throw <see cref="NotSupportedException"/>.
/// </para>
/// </remarks>
[Obsolete("RC2 (RFC 2268) is a weak legacy cipher with a reduced effective key length. Use AesGcmPkcs11 or AesCcmPkcs11. " +
          "RC2Pkcs11 throws InsecureOperationException unless the wrapped key's Pkcs11Workspace.AllowInsecure = true.",
    DiagnosticId = DiagnosticIds.Rc2,
    UrlFormat = DiagnosticIds.UrlFormat)]
public sealed class RC2Pkcs11 : RC2
{
    private readonly Pkcs11Key _key;

    /// <summary>
    /// Wraps a token-resident RC2 key. Borrowed — disposing this instance does not dispose the key.
    /// </summary>
    /// <param name="key">A PKCS#11 key whose <see cref="Pkcs11Key.KeyType"/> is <see cref="CKK.CKK_RC2"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="key"/> is not an RC2 key.</exception>
    public RC2Pkcs11(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_RC2)
            throw new ArgumentException($"Expected an RC2 key (CKK_RC2), got {key.KeyType}.", nameof(key));
        _key = key;

        // Reflect the token key's real size (CKA_VALUE_LEN, not sensitive) when it is a legal RC2 size,
        // so EffectiveKeySize defaults sensibly. Otherwise keep the base default (128).
        int? bits = TryReadKeySizeBits(key);
        if (bits is int b)
            KeySizeValue = b;
    }

    private static int? TryReadKeySizeBits(Pkcs11Key key)
    {
        try
        {
            var attrs = key.GetAttributeValue(CKA.CKA_VALUE_LEN);
            if (attrs.Count > 0 && !attrs[0].CannotBeRead)
            {
                int bytes = (int)attrs[0].GetValueAsUlong();
                // BCL RC2 legal key sizes are 40–128 bits in 8-bit steps (5–16 bytes).
                if (bytes is >= 5 and <= 16)
                    return bytes * 8;
            }
        }
        catch (Pkcs11Exception)
        {
            // Token doesn't expose CKA_VALUE_LEN — fall back to the base default.
        }
        return null;
    }

    /// <inheritdoc/>
    protected override bool TryEncryptCbcCore(
        ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv, Span<byte> destination, PaddingMode paddingMode, out int bytesWritten)
        => RunBlock(CbcMechanism(iv, paddingMode), encrypt: true, plaintext, destination, out bytesWritten);

    /// <inheritdoc/>
    protected override bool TryDecryptCbcCore(
        ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> iv, Span<byte> destination, PaddingMode paddingMode, out int bytesWritten)
        => RunBlock(CbcMechanism(iv, paddingMode), encrypt: false, ciphertext, destination, out bytesWritten);

    /// <inheritdoc/>
    protected override bool TryEncryptEcbCore(
        ReadOnlySpan<byte> plaintext, Span<byte> destination, PaddingMode paddingMode, out int bytesWritten)
        => RunBlock(EcbMechanism(paddingMode), encrypt: true, plaintext, destination, out bytesWritten);

    /// <inheritdoc/>
    protected override bool TryDecryptEcbCore(
        ReadOnlySpan<byte> ciphertext, Span<byte> destination, PaddingMode paddingMode, out int bytesWritten)
        => RunBlock(EcbMechanism(paddingMode), encrypt: false, ciphertext, destination, out bytesWritten);

    private bool RunBlock(Mechanism mechanism, bool encrypt, ReadOnlySpan<byte> input, Span<byte> destination, out int bytesWritten)
    {
        // Empty input is a no-op (0 bytes in → 0 bytes out): skip the token (some reject an empty
        // buffer) — but ONLY when AllowInsecure is set. With AllowInsecure off we fall through so
        // GuardMechanism throws InsecureOperationException as documented (the gate runs before the
        // empty buffer reaches the token). Padded encryption (CKM_RC2_CBC_PAD) must emit a full
        // padding block, so that path always goes to the token.
        if (input.IsEmpty && _key.AllowInsecure && !(encrypt && mechanism.Type == (ulong)CKM.CKM_RC2_CBC_PAD))
        {
            bytesWritten = 0;
            return true;
        }

        byte[] output = encrypt ? _key.Encrypt(mechanism, input) : _key.Decrypt(mechanism, input);
        try
        {
            if (output.Length > destination.Length)
            {
                bytesWritten = 0;
                return false;
            }
            output.CopyTo(destination);
            bytesWritten = output.Length;
            return true;
        }
        finally
        {
            // On decrypt, `output` is plaintext — zero this intermediate copy.
            if (!encrypt)
                CryptographicOperations.ZeroMemory(output);
        }
    }

    private Mechanism CbcMechanism(ReadOnlySpan<byte> iv, PaddingMode paddingMode)
    {
        ulong effectiveBits = ValidatedEffectiveBits();
        return paddingMode switch
        {
            PaddingMode.PKCS7 => new Mechanism(CKM.CKM_RC2_CBC_PAD, new CkmRc2CbcParams(effectiveBits, iv)),
            PaddingMode.None => new Mechanism(CKM.CKM_RC2_CBC, new CkmRc2CbcParams(effectiveBits, iv)),
            _ => throw new NotSupportedException(
                $"RC2Pkcs11 supports PKCS7 or None padding for CBC (CKM_RC2_CBC_PAD / CKM_RC2_CBC); got {paddingMode}."),
        };
    }

    private Mechanism EcbMechanism(PaddingMode paddingMode)
    {
        if (paddingMode != PaddingMode.None)
            throw new NotSupportedException(
                "RC2Pkcs11 supports only PaddingMode.None for ECB (PKCS#11 has no CKM_RC2_ECB_PAD). " +
                "Pre-pad the input, or use CBC with PKCS7.");
        return new Mechanism(CKM.CKM_RC2_ECB, new CkmRc2Params(ValidatedEffectiveBits()));
    }

    /// <summary>
    /// Returns <see cref="RC2.EffectiveKeySize"/> as the RC2 effective-key-bits mechanism parameter
    /// (RFC 2268), after checking it does not exceed the key's bit length
    /// (<see cref="SymmetricAlgorithm.KeySize"/>, reflected from the token's <c>CKA_VALUE_LEN</c>).
    /// Effective bits larger than the key bits would silently change the cipher; reject rather than
    /// forward an inconsistent value to the token.
    /// </summary>
    private ulong ValidatedEffectiveBits()
    {
        int effective = EffectiveKeySize;
        if (effective < 1 || effective > KeySize)
            throw new CryptographicException(
                $"RC2 effective key size ({effective} bits) must be between 1 and the key size ({KeySize} bits).");
        return (ulong)effective;
    }

    /// <summary>Generates a random initialization vector (8 bytes) for CBC mode.</summary>
    public override void GenerateIV() => IVValue = RandomNumberGenerator.GetBytes(BlockSize / 8);

    /// <summary>Not supported — the RC2 key is token-resident. Generate keys via <c>Pkcs11Workspace</c>.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override void GenerateKey() =>
        throw new NotSupportedException("RC2Pkcs11 wraps a token-resident key; generate keys via Pkcs11Workspace.GenerateKey instead.");

    /// <summary>Not supported — there is no <see cref="ICryptoTransform"/> over a non-extractable token key. Use the one-shot EncryptCbc/DecryptCbc API.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV) =>
        throw new NotSupportedException("RC2Pkcs11 does not expose an ICryptoTransform; use EncryptCbc / DecryptCbc / EncryptEcb / DecryptEcb.");

    /// <summary>Not supported — there is no <see cref="ICryptoTransform"/> over a non-extractable token key. Use the one-shot EncryptCbc/DecryptCbc API.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV) =>
        throw new NotSupportedException("RC2Pkcs11 does not expose an ICryptoTransform; use EncryptCbc / DecryptCbc / EncryptEcb / DecryptEcb.");

    /// <summary>Not supported — the wrapped key is token-resident and not extractable.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override byte[] Key
    {
        get => throw new NotSupportedException("The RC2 key is token-resident and not extractable; RC2Pkcs11 wraps a Pkcs11Key handle.");
        set => throw new NotSupportedException("RC2Pkcs11 wraps a token key; setting raw key bytes is not supported.");
    }
}
