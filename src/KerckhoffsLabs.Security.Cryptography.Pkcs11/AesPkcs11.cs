using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// BCL-aligned <see cref="Aes"/> implementation backed by a PKCS#11 token's AES block-cipher
/// mechanisms (<c>CKM_AES_CBC</c> / <c>CKM_AES_CBC_PAD</c> / <c>CKM_AES_ECB</c>), analogous to the
/// framework's <c>AesCng</c> (which is backed by Windows CNG). The key never enters managed memory —
/// this wraps a token-resident <see cref="Pkcs11Key"/> and does NOT take ownership of it.
/// </summary>
/// <remarks>
/// <para>
/// CBC and ECB provide confidentiality only, not integrity — they are malleable and (for CBC)
/// padding-oracle prone. Prefer authenticated encryption: <see cref="AesGcmPkcs11"/> or
/// <see cref="AesCcmPkcs11"/>. This type exists for legacy/interop scenarios.
/// </para>
/// <para>
/// Supported surface — the modern one-shot API runs on the token:
/// <list type="bullet">
/// <item><see cref="SymmetricAlgorithm.EncryptCbc(byte[], byte[], PaddingMode)"/> /
/// <c>DecryptCbc</c> with <see cref="PaddingMode.PKCS7"/> (→ <c>CKM_AES_CBC_PAD</c>, permitted by
/// default) or <see cref="PaddingMode.None"/> (→ <c>CKM_AES_CBC</c>, block-aligned input).</item>
/// <item><c>EncryptEcb</c> / <c>DecryptEcb</c> with <see cref="PaddingMode.None"/> (→ <c>CKM_AES_ECB</c>).</item>
/// </list>
/// Raw/unauthenticated modes — <see cref="PaddingMode.None"/> CBC (<c>CKM_AES_CBC</c>) and ECB
/// (<c>CKM_AES_ECB</c>) — are gated by the secure-defaults policy and throw
/// <c>InsecureOperationException</c> unless <see cref="Pkcs11Workspace.AllowInsecure"/> is set; only
/// <c>CKM_AES_CBC_PAD</c> is permitted by default. Empty input that yields empty output (any
/// decryption, or unpadded encryption) is a no-op returned without touching the token; empty
/// plaintext with PKCS7 must emit a padding block, so it is sent to the token (which must support
/// empty-input <c>CKM_AES_CBC_PAD</c> — SoftHSM, for example, does not).
/// </para>
/// <para>
/// NOT supported (a token key is not extractable, so the streaming/managed-key contract of
/// <see cref="SymmetricAlgorithm"/> does not apply): <see cref="CreateEncryptor(byte[], byte[])"/> /
/// <see cref="CreateDecryptor(byte[], byte[])"/> (no <see cref="ICryptoTransform"/>),
/// <see cref="GenerateKey"/> (generate via <c>Pkcs11Workspace</c> instead), the <see cref="Key"/>
/// property, CFB mode, and ECB/CBC with non-PKCS7/None padding. These throw
/// <see cref="NotSupportedException"/>.
/// </para>
/// </remarks>
public sealed class AesPkcs11 : Aes
{
    private readonly Pkcs11Key _key;

    /// <summary>
    /// Wraps a token-resident AES key. Borrowed — disposing this instance does not dispose the key.
    /// </summary>
    /// <param name="key">A PKCS#11 key whose <see cref="Pkcs11Key.KeyType"/> is <see cref="CKK.CKK_AES"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="key"/> is not an AES key.</exception>
    public AesPkcs11(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_AES)
            throw new ArgumentException($"Expected an AES key, got {key.KeyType}.", nameof(key));
        _key = key;

        // Reflect the token key's real size (CKA_VALUE_LEN is the byte length and is not sensitive).
        // Best-effort: the Aes base constructor leaves KeySize=256, which we keep if the token does
        // not expose the length. BlockSize stays 128 and the legal-size tables are set by the base.
        int? bits = TryReadKeySizeBits(key);
        if (bits is int b)
            KeySizeValue = b;
    }

    private static int? TryReadKeySizeBits(Pkcs11Key key)
    {
        try
        {
            var attrs = key.Workspace.Session.GetAttributeValue(key.PrivateHandle, [CKA.CKA_VALUE_LEN]);
            if (attrs.Count > 0 && !attrs[0].CannotBeRead)
            {
                int bytes = (int)attrs[0].GetValueAsUlong();
                if (bytes is 16 or 24 or 32)
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
        using (mechanism)
        {
            // Empty input is a no-op (0 bytes in → 0 bytes out) returned without touching the token:
            // there is nothing to do, and some tokens (e.g. SoftHSM) reject an empty C_Encrypt /
            // C_Decrypt buffer. The exception is padded encryption (CKM_AES_CBC_PAD), where the BCL
            // contract requires a full padding block to be emitted, so that path goes to the token.
            if (input.IsEmpty && !(encrypt && mechanism.Type == (ulong)CKM.CKM_AES_CBC_PAD))
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
                // On decrypt, `output` is plaintext — zero this intermediate copy (the caller still
                // receives the plaintext via `destination`). Ciphertext on encrypt is not sensitive.
                if (!encrypt)
                    CryptographicOperations.ZeroMemory(output);
            }
        }
    }

    private static Mechanism CbcMechanism(ReadOnlySpan<byte> iv, PaddingMode paddingMode) => paddingMode switch
    {
        PaddingMode.PKCS7 => new Mechanism(CKM.CKM_AES_CBC_PAD, iv.ToArray()),
        PaddingMode.None => new Mechanism(CKM.CKM_AES_CBC, iv.ToArray()),
        _ => throw new NotSupportedException(
            $"AesPkcs11 supports PKCS7 or None padding for CBC (CKM_AES_CBC_PAD / CKM_AES_CBC); got {paddingMode}."),
    };

    private static Mechanism EcbMechanism(PaddingMode paddingMode) => paddingMode switch
    {
        PaddingMode.None => new Mechanism(CKM.CKM_AES_ECB),
        _ => throw new NotSupportedException(
            "AesPkcs11 supports only PaddingMode.None for ECB (PKCS#11 has no CKM_AES_ECB_PAD). " +
            "Pre-pad the input, or use CBC with PKCS7."),
    };

    /// <summary>Generates a random initialization vector (16 bytes) for CBC mode.</summary>
    public override void GenerateIV() => IVValue = RandomNumberGenerator.GetBytes(BlockSize / 8);

    /// <summary>Not supported — the AES key is token-resident. Generate keys via <c>Pkcs11Workspace</c>.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override void GenerateKey() =>
        throw new NotSupportedException("AesPkcs11 wraps a token-resident key; generate keys via Pkcs11Workspace.GenerateKey instead.");

    /// <summary>Not supported — there is no <see cref="ICryptoTransform"/> over a non-extractable token key. Use the one-shot EncryptCbc/DecryptCbc API.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV) =>
        throw new NotSupportedException("AesPkcs11 does not expose an ICryptoTransform; use EncryptCbc / DecryptCbc / EncryptEcb / DecryptEcb.");

    /// <summary>Not supported — there is no <see cref="ICryptoTransform"/> over a non-extractable token key. Use the one-shot EncryptCbc/DecryptCbc API.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV) =>
        throw new NotSupportedException("AesPkcs11 does not expose an ICryptoTransform; use EncryptCbc / DecryptCbc / EncryptEcb / DecryptEcb.");

    /// <summary>Not supported — the wrapped key is token-resident and not extractable.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override byte[] Key
    {
        get => throw new NotSupportedException("The AES key is token-resident and not extractable; AesPkcs11 wraps a Pkcs11Key handle.");
        set => throw new NotSupportedException("AesPkcs11 wraps a token key; setting raw key bytes is not supported.");
    }
}
