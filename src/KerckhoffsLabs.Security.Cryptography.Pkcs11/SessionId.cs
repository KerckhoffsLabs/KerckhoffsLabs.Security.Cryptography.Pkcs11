// Licensed under the MIT License

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Strongly-typed identifier of a PKCS#11 session (<c>CK_SESSION_HANDLE</c>), as surfaced by
/// <see cref="SessionInfo"/> for diagnostics and log correlation.
/// </summary>
/// <remarks>
/// Wraps the raw session handle in a dedicated value type — the same pattern the library uses
/// for object handles — so it cannot be mixed with slot numbers or other integers. Session
/// handles are transient, process-local values produced only by the module; the constructor is
/// <c>internal</c> because a consumer-fabricated handle has nothing valid to be compared against
/// or used for.
/// </remarks>
public readonly record struct SessionId
{
    private readonly ulong _value;

    /// <summary>Initializes a session identifier wrapping the given raw session handle.</summary>
    internal SessionId(ulong value) => _value = value;

    /// <summary>The raw <c>CK_SESSION_HANDLE</c> value as an unsigned 64-bit integer.</summary>
    public ulong Value => _value;

    /// <summary>The session handle in hexadecimal (handles are opaque, not ordinals).</summary>
    public override string ToString() => $"0x{_value:X}";
}
