using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// High-level wrapper for <see cref="CK_AES_CTR_PARAMS"/>, the parameter of <c>CKM_AES_CTR</c>
/// (PKCS#11 v3.2 §6.11.2): the number of low-order counter bits to increment, and the 16-byte
/// initial counter block. A managed descriptor: it holds a private copy of the block and is rebuilt
/// into each call's own scope, so one instance may safely back several mechanisms. The counter
/// width is written at the platform's <c>CK_ULONG</c> width (4 bytes on Windows, 8 on LP64).
/// </summary>
/// <remarks>
/// <c>CKM_AES_CTR</c> is unauthenticated: the ciphertext is malleable and a counter block must never
/// repeat under one key. <c>CryptoPolicy.Recommended</c> refuses the mechanism for that reason;
/// <c>CryptoPolicy.NistApproved</c> allows it (SP 800-38A). Prefer AES-GCM unless the protocol
/// requires CTR.
/// </remarks>
public sealed class CkmAesCtrParams : MechanismParameters
{
    private const int BlockLength = 16;

    private readonly byte[] _counterBlock;
    private readonly int _counterBits;

    /// <summary>
    /// Initializes the CTR parameters with a counter that increments over the whole 128-bit block.
    /// </summary>
    /// <param name="counterBlock">The initial counter block, exactly 16 bytes; copied.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="counterBlock"/> is not exactly 16 bytes.</exception>
    public CkmAesCtrParams(ReadOnlySpan<byte> counterBlock) : this(128, counterBlock) { }

    /// <summary>
    /// Initializes the CTR parameters.
    /// </summary>
    /// <param name="counterBits">The number of low-order bits of the counter block the token increments
    /// (big-endian), in [1, 128]. The bits above them (a nonce, say) never change. A token refuses a
    /// message long enough to overflow these bits with <c>CKR_DATA_LEN_RANGE</c>.</param>
    /// <param name="counterBlock">The initial counter block, exactly 16 bytes; copied.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="counterBits"/> is not in [1, 128].</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="counterBlock"/> is not exactly 16 bytes.</exception>
    public CkmAesCtrParams(int counterBits, ReadOnlySpan<byte> counterBlock)
    {
        if (counterBits is < 1 or > 128)
            throw new ArgumentOutOfRangeException(nameof(counterBits), counterBits, "The counter width must be in [1, 128] bits.");
        if (counterBlock.Length != BlockLength)
            throw new ArgumentException("The AES-CTR counter block must be exactly 16 bytes.", nameof(counterBlock));

        _counterBits = counterBits;
        _counterBlock = counterBlock.ToArray();
    }

    /// <inheritdoc/>
    internal override Pkcs11ParameterBlock BuildMarshalable(MechanismParameterScope scope)
    {
        // The counter block is an inline buffer, which an object initializer cannot assign from a span,
        // so construct first and copy into the field afterwards.
        var lowLevel = new CK_AES_CTR_PARAMS { CounterBits = (NativeCULong)(ulong)_counterBits };
        _counterBlock.CopyTo(lowLevel.Cb);
        return scope.WriteParameter(lowLevel);
    }
}
