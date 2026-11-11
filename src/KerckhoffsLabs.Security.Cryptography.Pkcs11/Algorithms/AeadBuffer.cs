using System.Buffers;
using System.Security.Cryptography;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// The AEAD wrappers' short-lived buffer for ciphertext followed by the tag, the one run PKCS#11's
/// single-part calls read and write. Pooled up to <see cref="MaxPooledLength"/>, and zeroized on every
/// return, because what passes through it is often plaintext.
/// </summary>
/// <remarks>
/// The session core has its own; the wrappers keep a copy rather than reach into <c>Internal</c>, since
/// they are built on the library's public API only.
/// </remarks>
internal static class AeadBuffer
{
    /// <summary>
    /// The largest buffer taken from the shared pool. A larger one is allocated and dropped, so a single
    /// huge operation does not leave the pool holding a buffer of that size for the life of the process.
    /// </summary>
    internal const int MaxPooledLength = 1 << 20;

    /// <summary>A buffer of at least <paramref name="length"/> bytes. Use only its first <paramref name="length"/>.</summary>
    internal static byte[] Rent(int length)
        => length <= MaxPooledLength ? ArrayPool<byte>.Shared.Rent(length) : new byte[length];

    /// <summary>
    /// Zeroizes all of <paramref name="buffer"/>, not just the part written: a pooled array can be
    /// larger than was asked for, and nothing may survive in it for the next renter.
    /// </summary>
    internal static void Return(byte[] buffer)
    {
        CryptographicOperations.ZeroMemory(buffer);
        if (buffer.Length <= MaxPooledLength)
            ArrayPool<byte>.Shared.Return(buffer);
    }
}
