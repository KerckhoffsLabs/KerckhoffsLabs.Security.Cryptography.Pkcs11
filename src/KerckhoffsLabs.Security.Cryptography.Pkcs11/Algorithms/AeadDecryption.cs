using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// The AEAD wrappers' token decrypt calls, reporting a failed tag check the way the BCL does: as an
/// <see cref="AuthenticationTagMismatchException"/>, the type <see cref="AesGcm"/>, <see cref="AesCcm"/>
/// and <see cref="ChaCha20Poly1305"/> callers catch to detect tampering, with the caller's plaintext
/// destination cleared first.
/// </summary>
/// <remarks>
/// <para>
/// Modules report a failed tag check with different codes: <see cref="CKR.CKR_AEAD_DECRYPT_FAILED"/>
/// (v3.0 and later), <see cref="CKR.CKR_ENCRYPTED_DATA_INVALID"/> (SoftHSM and most v2.40 modules) and
/// <see cref="CKR.CKR_SIGNATURE_INVALID"/> (modules that treat the tag as a MAC).
/// <see cref="CKR.CKR_ENCRYPTED_DATA_INVALID"/> can also mean malformed input in general, but the
/// wrappers check the nonce, tag and buffer lengths before calling the token, so here the tag is what
/// failed. The module's <see cref="Pkcs11Exception"/> is kept as the
/// <see cref="Exception.InnerException"/>, so its return code stays readable. Every other code
/// propagates unchanged.
/// </para>
/// <para>
/// Methods rather than a <c>try</c>/<c>catch</c>-wrapping delegate helper: the calls take
/// <c>ReadOnlySpan&lt;byte&gt;</c> arguments, which a lambda closure cannot capture.
/// </para>
/// </remarks>
internal static class AeadDecryption
{
    /// <summary>
    /// Single-part <c>C_Decrypt</c> of <paramref name="ciphertextAndTag"/>. If the tag does not verify,
    /// <paramref name="plaintext"/>, the caller's destination, is cleared before the throw.
    /// </summary>
    public static byte[] Decrypt(
        Pkcs11Key key, Mechanism mechanism, ReadOnlySpan<byte> ciphertextAndTag, Span<byte> plaintext)
    {
        try
        {
            return key.Decrypt(mechanism, ciphertextAndTag);
        }
        catch (Pkcs11Exception ex) when (IsTagMismatch(ex.ReturnValue))
        {
            throw TagMismatch(ex, plaintext);
        }
    }

    /// <summary>
    /// PKCS#11 v3.0 message-based <c>C_DecryptMessage</c> of <paramref name="ciphertext"/>. If the tag does
    /// not verify, <paramref name="plaintext"/>, the caller's destination, is cleared before the throw.
    /// </summary>
    public static byte[] MessageDecrypt(
        Pkcs11Key key,
        Mechanism mechanism,
        MechanismParameters messageParams,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> plaintext)
    {
        try
        {
            return key.MessageDecrypt(mechanism, messageParams, associatedData, ciphertext);
        }
        catch (Pkcs11Exception ex) when (IsTagMismatch(ex.ReturnValue))
        {
            throw TagMismatch(ex, plaintext);
        }
    }

    /// <summary>Whether <paramref name="returnValue"/> is a module's report of a failed AEAD tag check.</summary>
    public static bool IsTagMismatch(CKR returnValue) =>
        returnValue is CKR.CKR_AEAD_DECRYPT_FAILED or CKR.CKR_ENCRYPTED_DATA_INVALID or CKR.CKR_SIGNATURE_INVALID;

    private static AuthenticationTagMismatchException TagMismatch(Pkcs11Exception inner, Span<byte> plaintext)
    {
        CryptographicOperations.ZeroMemory(plaintext);
        return new AuthenticationTagMismatchException(
            "The authentication tag does not match the ciphertext; the data was not decrypted.", inner);
    }
}
