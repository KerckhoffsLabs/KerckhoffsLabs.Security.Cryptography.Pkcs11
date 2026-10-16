using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11SessionCore
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

        Log.SessionTrace(_logger, (ulong)_sessionId, "SeedRandom");

        // The caller's entropy goes straight to the token: no copy to zero on the way out.
        CKR rv = _pkcs11Library.C_SeedRandom(_sessionId, seed);
        Pkcs11Exception.ThrowIfError(rv, OpSeedRandom);
    }

    /// <summary>
    /// Mixes additional seed material into the token's random number generator
    /// </summary>
    /// <param name="seed">Seed material</param>
    public void SeedRandom(byte[] seed)
    {
        using var _ = AcquireExclusive();

        Log.SessionTrace(_logger, (ulong)_sessionId, "SeedRandom");

        ArgumentNullException.ThrowIfNull(seed);

        CKR rv = _pkcs11Library.C_SeedRandom(_sessionId, seed);
        Pkcs11Exception.ThrowIfError(rv, OpSeedRandom);
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

        Log.SessionTrace(_logger, (ulong)_sessionId, "GenerateRandom");

        // The token fills the caller's span directly. There is no transient array holding a second
        // copy of freshly generated key material, which is the point of passing a span you control.
        CKR rv = _pkcs11Library.C_GenerateRandom(_sessionId, destination);
        Pkcs11Exception.ThrowIfError(rv, OpGenerateRandom);
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

        Log.SessionTrace(_logger, (ulong)_sessionId, "GenerateRandom");

        if (length < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(length));

        byte[] randomData = new byte[length];
        CKR rv = _pkcs11Library.C_GenerateRandom(_sessionId, randomData);
        Pkcs11Exception.ThrowIfError(rv, OpGenerateRandom);

        return randomData;
    }
}
