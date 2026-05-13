using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

public sealed partial class Pkcs11Workspace
{
    /// <summary>
    /// Reads <paramref name="length"/> bytes from the token's RNG.
    /// </summary>
    /// <param name="length">Number of bytes to generate. Must be &gt; 0.</param>
    /// <returns>A newly allocated byte array of length <paramref name="length"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="length"/> is &lt;= 0.</exception>
    public byte[] GenerateRandom(int length)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (length <= 0)
            throw new ArgumentOutOfRangeException(nameof(length), "Length must be > 0.");
        return _session.GenerateRandom(length);
    }

    /// <summary>
    /// Seeds the token's RNG with the supplied bytes. Optional — many tokens ignore seed
    /// data because they use hardware entropy.
    /// </summary>
    /// <param name="seed">Seed bytes. Must not be empty.</param>
    public void SeedRandom(ReadOnlySpan<byte> seed)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (seed.IsEmpty)
            throw new ArgumentException("Seed must not be empty.", nameof(seed));
        _session.SeedRandom(seed);
    }

    /// <summary>
    /// Computes a one-shot digest over <paramref name="data"/> using the given mechanism.
    /// </summary>
    /// <param name="mechanism">Digest mechanism (e.g. <see cref="Mechanism"/> wrapping <see cref="CKM.CKM_SHA256"/>).</param>
    /// <param name="data">The data to digest.</param>
    /// <returns>The digest bytes.</returns>
    public byte[] Digest(Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(mechanism);
        return _session.Digest(mechanism, data);
    }
}
