using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
    /// <summary>
    /// Mixes additional seed material into the token's random number generator
    /// </summary>
    /// <param name="seed">Seed material</param>
    public void SeedRandom(byte[] seed)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::SeedRandom", _sessionId);

        if (seed == null)
            throw new ArgumentNullException("seed");

        CKR rv = _pkcs11Library.C_SeedRandom(_sessionId, seed, (NativeCULong)(seed.Length));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SeedRandom", rv);
    }

    /// <summary>
    /// Generates random or pseudo-random data
    /// </summary>
    /// <param name="length">Length in bytes of the random or pseudo-random data to be generated</param>
    /// <returns>Generated random or pseudo-random data</returns>
    public byte[] GenerateRandom(int length)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::GenerateRandom", _sessionId);

        if (length < 1)
            throw new ArgumentException("Value has to be positive number", "length");

        byte[] randomData = new byte[length];
        CKR rv = _pkcs11Library.C_GenerateRandom(_sessionId, randomData, (NativeCULong)(length));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GenerateRandom", rv);

        return randomData;
    }
}
