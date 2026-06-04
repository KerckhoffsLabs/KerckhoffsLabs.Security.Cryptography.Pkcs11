using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// BCL-aligned <see cref="DES"/> implementation backed by a PKCS#11 token's single-DES block-cipher
/// mechanisms (<c>CKM_DES_CBC</c> / <c>CKM_DES_CBC_PAD</c> / <c>CKM_DES_ECB</c>), analogous to the
/// framework's <c>DESCryptoServiceProvider</c>. The key never enters managed memory — this wraps a
/// token-resident <see cref="Pkcs11Key"/> and does NOT take ownership of it.
/// </summary>
/// <remarks>
/// <para>
/// Single DES has a 56-bit effective key and is exhaustively breakable; it is provided only for
/// interop with legacy systems. Like <see cref="AesPkcs11"/>, every operation throws
/// <c>InsecureOperationException</c> unless <see cref="Pkcs11Workspace.AllowInsecure"/> is set on the
/// wrapped key's workspace — and unlike AES there is no authenticated DES mode to fall back to.
/// Prefer <see cref="AesGcmPkcs11"/> or <see cref="AesCcmPkcs11"/>; this type exists only for legacy
/// decrypt/interop scenarios.
/// </para>
/// <para>
/// Supported modes (on the token, once AllowInsecure is set):
/// <list type="bullet">
/// <item>CBC — <see cref="SymmetricAlgorithm.EncryptCbc(byte[], byte[], PaddingMode)"/> / <c>DecryptCbc</c>
/// with <see cref="PaddingMode.PKCS7"/> (→ <c>CKM_DES_CBC_PAD</c>) or <see cref="PaddingMode.None"/>
/// (→ <c>CKM_DES_CBC</c>, block-aligned input).</item>
/// <item>ECB — <c>EncryptEcb</c> / <c>DecryptEcb</c> with <see cref="PaddingMode.None"/> (→ <c>CKM_DES_ECB</c>).</item>
/// </list>
/// Empty input that yields empty output (any decryption, or unpadded encryption) is a no-op returned
/// without touching the token; empty plaintext with PKCS7 must emit a padding block, so it is sent to
/// the token (which must support empty-input <c>CKM_DES_CBC_PAD</c>).
/// </para>
/// <para>
/// NOT supported: CFB/OFB stream modes (the secure-defaults gate in <c>Pkcs11Session</c> does not
/// cover single-DES <c>CKM_DES_CFB*/OFB*</c>, so enabling them here would bypass <c>AllowInsecure</c>);
/// <see cref="CreateEncryptor(byte[], byte[])"/> / <see cref="CreateDecryptor(byte[], byte[])"/> (no
/// <see cref="ICryptoTransform"/> over a non-extractable token key); <see cref="GenerateKey"/>
/// (generate via <c>Pkcs11Workspace</c> instead); the <see cref="Key"/> property; and any padding
/// other than PKCS7/None. These throw <see cref="NotSupportedException"/>.
/// </para>
/// </remarks>
[Obsolete("Single DES has a 56-bit key and is exhaustively breakable. Use AesGcmPkcs11 or AesCcmPkcs11. " +
          "DESPkcs11 throws InsecureOperationException unless the wrapped key's Pkcs11Workspace.AllowInsecure = true.")]
public sealed class DESPkcs11 : DES
{
    private readonly Pkcs11Key _key;

    /// <summary>
    /// Wraps a token-resident DES key. Borrowed — disposing this instance does not dispose the key.
    /// </summary>
    /// <param name="key">A PKCS#11 key whose <see cref="Pkcs11Key.KeyType"/> is <see cref="CKK.CKK_DES"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="key"/> is not a single-DES key.</exception>
    public DESPkcs11(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeyType != CKK.CKK_DES)
            throw new ArgumentException($"Expected a single-DES key (CKK_DES), got {key.KeyType}.", nameof(key));
        _key = key;

        // Single DES is a fixed 64-bit (8-byte, with parity) key and 64-bit block; the DES base
        // constructor already sets KeySize/BlockSize/legal-size tables, so there is nothing to
        // reflect from the token (unlike AES, whose key length varies).
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
            // there is nothing to do, and some tokens reject an empty C_Encrypt / C_Decrypt buffer.
            // The exception is padded encryption (CKM_DES_CBC_PAD), where the BCL contract requires a
            // full padding block to be emitted, so that path goes to the token.
            if (input.IsEmpty && !(encrypt && mechanism.Type == (ulong)CKM.CKM_DES_CBC_PAD))
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
        PaddingMode.PKCS7 => new Mechanism(CKM.CKM_DES_CBC_PAD, iv.ToArray()),
        PaddingMode.None => new Mechanism(CKM.CKM_DES_CBC, iv.ToArray()),
        _ => throw new NotSupportedException(
            $"DESPkcs11 supports PKCS7 or None padding for CBC (CKM_DES_CBC_PAD / CKM_DES_CBC); got {paddingMode}."),
    };

    private static Mechanism EcbMechanism(PaddingMode paddingMode) => paddingMode switch
    {
        PaddingMode.None => new Mechanism(CKM.CKM_DES_ECB),
        _ => throw new NotSupportedException(
            "DESPkcs11 supports only PaddingMode.None for ECB (PKCS#11 has no CKM_DES_ECB_PAD). " +
            "Pre-pad the input, or use CBC with PKCS7."),
    };

    /// <summary>Generates a random initialization vector (8 bytes) for CBC mode.</summary>
    public override void GenerateIV() => IVValue = RandomNumberGenerator.GetBytes(BlockSize / 8);

    /// <summary>Not supported — the DES key is token-resident. Generate keys via <c>Pkcs11Workspace</c>.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override void GenerateKey() =>
        throw new NotSupportedException("DESPkcs11 wraps a token-resident key; generate keys via Pkcs11Workspace.GenerateKey instead.");

    /// <summary>Not supported — there is no <see cref="ICryptoTransform"/> over a non-extractable token key. Use the one-shot EncryptCbc/DecryptCbc API.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV) =>
        throw new NotSupportedException("DESPkcs11 does not expose an ICryptoTransform; use EncryptCbc / DecryptCbc / EncryptEcb / DecryptEcb.");

    /// <summary>Not supported — there is no <see cref="ICryptoTransform"/> over a non-extractable token key. Use the one-shot EncryptCbc/DecryptCbc API.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV) =>
        throw new NotSupportedException("DESPkcs11 does not expose an ICryptoTransform; use EncryptCbc / DecryptCbc / EncryptEcb / DecryptEcb.");

    /// <summary>Not supported — the wrapped key is token-resident and not extractable.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override byte[] Key
    {
        get => throw new NotSupportedException("The DES key is token-resident and not extractable; DESPkcs11 wraps a Pkcs11Key handle.");
        set => throw new NotSupportedException("DESPkcs11 wraps a token key; setting raw key bytes is not supported.");
    }
}
