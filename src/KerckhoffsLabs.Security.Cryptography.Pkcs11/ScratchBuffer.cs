using System.Buffers;
using System.Security.Cryptography;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Short-lived byte buffers for output that has to land somewhere other than the caller's span first:
/// a module that wants a larger buffer than the result needs, or an AEAD whose ciphertext and tag the
/// token writes as one run. Pooled up to <see cref="MaxPooledLength"/>, and zeroized on every return,
/// because what passes through them is often plaintext.
/// </summary>
/// <remarks>
/// In the root namespace so the session core and the <c>Algorithms</c> adapters share one pooling and
/// zeroizing rule; the adapters may not reach into <c>Internal</c>.
/// </remarks>
internal static class ScratchBuffer
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
