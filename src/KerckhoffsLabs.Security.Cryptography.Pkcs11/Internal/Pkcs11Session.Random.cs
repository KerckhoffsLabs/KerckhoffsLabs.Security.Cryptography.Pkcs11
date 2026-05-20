using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11Session
{
    /// <summary>
    /// Seeds the token's random number generator with caller-supplied entropy. Useful when
    /// the host has access to high-quality entropy (e.g., another RNG) that the caller wants
    /// to mix into the token's internal state. Most callers should rely solely on the token's
    /// internal RNG and call <see cref="GenerateRandom(int)"/> directly.
    /// </summary>
    /// <param name="seed">Entropy bytes to mix into the token RNG.</param>
    public void SeedRandom(ReadOnlySpan<byte> seed)
    {
        using var _ = AcquireExclusive();
        byte[] buffer = seed.ToArray();
        SeedRandom(buffer);
    }

    /// <summary>
    /// Mixes additional seed material into the token's random number generator
    /// </summary>
    /// <param name="seed">Seed material</param>
    public void SeedRandom(byte[] seed)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        _logger.LogDebug("Session({SessionId})::SeedRandom", _sessionId);

        ArgumentNullException.ThrowIfNull(seed);

        CKR rv = _pkcs11Library.C_SeedRandom(_sessionId, seed, (NativeCULong)(seed.Length));
        Pkcs11Exception.ThrowIfError(rv, "C_SeedRandom");
    }

    /// <summary>
    /// Fills <paramref name="destination"/> with random bytes from the token's RNG and
    /// returns the number of bytes written.
    /// </summary>
    /// <param name="destination">Buffer to fill. The full length of <paramref name="destination"/> is filled.</param>
    /// <returns>Number of bytes written (equal to <paramref name="destination"/>.Length).</returns>
    public int GenerateRandom(Span<byte> destination)
    {
        using var _ = AcquireExclusive();
        if (destination.IsEmpty) return 0;
        byte[] random = GenerateRandom(destination.Length);
        random.CopyTo(destination);
        return destination.Length;
    }

    /// <summary>
    /// Generates random or pseudo-random data
    /// </summary>
    /// <param name="length">Length in bytes of the random or pseudo-random data to be generated</param>
    /// <returns>Generated random or pseudo-random data</returns>
    public byte[] GenerateRandom(int length)
    {
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        _logger.LogDebug("Session({SessionId})::GenerateRandom", _sessionId);

        if (length < 1)
            throw new ArgumentException("Value has to be positive number", "length");

        byte[] randomData = new byte[length];
        CKR rv = _pkcs11Library.C_GenerateRandom(_sessionId, randomData, (NativeCULong)(length));
        Pkcs11Exception.ThrowIfError(rv, "C_GenerateRandom");

        return randomData;
    }
}
