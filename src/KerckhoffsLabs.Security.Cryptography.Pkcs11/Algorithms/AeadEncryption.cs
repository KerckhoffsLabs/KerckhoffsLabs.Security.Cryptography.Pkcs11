using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// The AEAD wrappers' token encrypt calls, writing the ciphertext into the caller's span rather than
/// into an array that is then copied.
/// </summary>
internal static class AeadEncryption
{
    // Each method's operation argument names the operation in its errors, e.g. "AES-GCM encrypt".

    /// <summary>
    /// PKCS#11 v3.0 message-based <c>C_EncryptMessage</c> of <paramref name="plaintext"/> straight into
    /// <paramref name="ciphertext"/>; the tag stays in <paramref name="messageParams"/>.
    /// </summary>
    public static void MessageEncrypt(Pkcs11Key key, Mechanism mechanism, MechanismParameters messageParams,
        ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, string operation)
    {
        if (!key.TryMessageEncryptInto(mechanism, messageParams, associatedData, plaintext, ciphertext, out int written)
            || written != plaintext.Length)
            throw new InvalidOperationException($"{operation} returned {written} bytes; expected {plaintext.Length}.");
    }

    /// <summary>
    /// Single-part <c>C_Encrypt</c>, whose output is the ciphertext followed by the tag, split into
    /// <paramref name="ciphertext"/> and <paramref name="tag"/> through one <see cref="ScratchBuffer"/>.
    /// </summary>
    public static void EncryptConcatenated(Pkcs11Key key, Mechanism mechanism, ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext, Span<byte> tag, string operation)
    {
        int length = plaintext.Length + tag.Length;
        byte[] output = ScratchBuffer.Rent(length);
        try
        {
            if (!key.TryEncryptInto(mechanism, plaintext, output.AsSpan(0, length), out int written) || written != length)
                throw new InvalidOperationException($"{operation} returned {written} bytes; expected {length}.");
            output.AsSpan(0, plaintext.Length).CopyTo(ciphertext);
            output.AsSpan(plaintext.Length, tag.Length).CopyTo(tag);
        }
        finally
        {
            ScratchBuffer.Return(output);
        }
    }
}
