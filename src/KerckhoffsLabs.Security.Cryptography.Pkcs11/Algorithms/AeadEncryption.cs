namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// The AEAD wrappers' single-part token encrypt, writing the ciphertext and tag into the caller's spans
/// rather than into an array that is then copied.
/// </summary>
internal static class AeadEncryption
{
    // The operation argument names the operation in errors, e.g. "AES-GCM encrypt".

    /// <summary>
    /// Single-part <c>C_Encrypt</c>, whose output is the ciphertext followed by the tag, split into
    /// <paramref name="ciphertext"/> and <paramref name="tag"/> through one <see cref="AeadBuffer"/>.
    /// </summary>
    public static void EncryptConcatenated(Pkcs11Key key, Mechanism mechanism, ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext, Span<byte> tag, string operation)
    {
        int length = plaintext.Length + tag.Length;
        byte[] output = AeadBuffer.Rent(length);
        try
        {
            if (!key.TryEncrypt(mechanism, plaintext, output.AsSpan(0, length), out int written))
                throw new InvalidOperationException($"{operation} returned more than {length} bytes.");
            if (written != length)
                throw new InvalidOperationException($"{operation} returned {written} bytes; expected {length}.");
            output.AsSpan(0, plaintext.Length).CopyTo(ciphertext);
            output.AsSpan(plaintext.Length, tag.Length).CopyTo(tag);
        }
        finally
        {
            AeadBuffer.Return(output);
        }
    }
}
