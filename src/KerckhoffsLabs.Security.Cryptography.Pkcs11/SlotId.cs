using System.Globalization;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Strongly-typed identifier of a PKCS#11 slot (<c>CK_SLOT_ID</c>).
/// </summary>
/// <remarks>
/// <para>
/// Wraps the raw slot number in a dedicated value type — the same pattern the library uses for
/// object handles — so a slot identifier cannot be accidentally mixed with session handles,
/// counts, or other integers. The shape follows BCL opaque-identity types
/// (<c>readonly record struct</c> with value equality and no heap allocation).
/// </para>
/// <para>
/// Unlike session or object handles, slot numbers are stable, externally meaningful values: they
/// appear in vendor tooling and configuration files (e.g. "use slot 3"). The constructor is
/// therefore public so a consumer can build a <see cref="SlotId"/> from configuration and compare
/// it against <see cref="Pkcs11Slot.SlotId"/>.
/// </para>
/// </remarks>
public readonly record struct SlotId
{
    private readonly ulong _value;

    /// <summary>Initializes a slot identifier wrapping the given raw slot number.</summary>
    /// <param name="value">The raw <c>CK_SLOT_ID</c> value.</param>
    public SlotId(ulong value) => _value = value;

    /// <summary>The raw <c>CK_SLOT_ID</c> value as an unsigned 64-bit integer.</summary>
    public ulong Value => _value;

    /// <summary>The slot number in decimal, matching how vendor tools display slot ids.</summary>
    public override string ToString() => _value.ToString(CultureInfo.InvariantCulture);
}
