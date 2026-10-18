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
/// Some modules report a failed tag check with a generic code instead: SoftHSM 2.5 returns
/// <see cref="CKR.CKR_GENERAL_ERROR"/> for AES-GCM, and Kryoptic returns <see cref="CKR.CKR_DEVICE_ERROR"/>
/// for AES-CCM through <c>C_DecryptMessage</c>. Those codes are deliberately not mapped: nothing tells
/// them apart from a genuine module fault, and reporting a fault as tampering would mislead the caller.
/// On such modules the forgery is still rejected, as a <see cref="Pkcs11Exception"/>.
/// </para>
/// <para>
/// Methods rather than a <see langword="try"/>/<see langword="catch"/>-wrapping delegate helper: the calls take
/// <c>ReadOnlySpan&lt;byte&gt;</c> arguments, which a lambda closure cannot capture.
/// </para>
/// </remarks>
internal static class AeadDecryption
{
    // Each method's operation argument, where it has one, names the operation in errors, e.g. "AES-GCM decrypt".

    /// <summary>
    /// Single-part <c>C_Decrypt</c> of <paramref name="ciphertext"/> followed by <paramref name="tag"/>,
    /// the input layout PKCS#11 expects, straight into <paramref name="plaintext"/>. The input is
    /// assembled in an <see cref="AeadBuffer"/>. If the tag does not verify, or the plaintext is not
    /// exactly <paramref name="plaintext"/>'s length, <paramref name="plaintext"/> is cleared before the
    /// throw.
    /// </summary>
    public static void DecryptConcatenated(Pkcs11Key key, Mechanism mechanism, ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag, Span<byte> plaintext, string operation)
    {
        int length = ciphertext.Length + tag.Length;
        byte[] input = AeadBuffer.Rent(length);
        try
        {
            ciphertext.CopyTo(input);
            tag.CopyTo(input.AsSpan(ciphertext.Length));

            bool fits;
            int written;
            try
            {
                fits = key.TryDecrypt(mechanism, input.AsSpan(0, length), plaintext, out written);
            }
            catch (Pkcs11Exception ex) when (IsTagMismatch(ex.ReturnValue))
            {
                throw TagMismatch(ex, plaintext);
            }

            if (!fits)
                throw new InvalidOperationException($"{operation} returned more than {plaintext.Length} bytes.");
            if (written != plaintext.Length)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw new InvalidOperationException($"{operation} returned {written} bytes; expected {plaintext.Length}.");
            }
        }
        finally
        {
            AeadBuffer.Return(input);
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
