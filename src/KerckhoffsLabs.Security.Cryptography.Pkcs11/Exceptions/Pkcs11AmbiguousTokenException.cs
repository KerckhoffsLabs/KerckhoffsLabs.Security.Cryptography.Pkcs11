using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

/// <summary>
/// Raised when a lookup that must identify exactly one token, such as <see cref="Pkcs11Library.GetSlotByTokenLabel"/>
/// or <see cref="Pkcs11Library.GetSlotByUri(Pkcs11Uri)"/>, matched more than one present token.
/// </summary>
/// <remarks>
/// <para>
/// Picking one would let whoever can initialize a token decide which one the application uses, so the lookup refuses
/// instead. Select the token by what tells them apart: its serial number, a PKCS#11 URI with its manufacturer or model,
/// or a predicate (<see cref="Pkcs11Library.GetSlot"/>). <see cref="SlotIds"/> names the matching slots, for a report
/// only: a slot ID is the module's and may change between runs.
/// </para>
/// <para>
/// Raised by the library itself, as <see cref="Pkcs11AmbiguousObjectException"/> is for objects: every call succeeded,
/// so <see cref="Pkcs11Exception.ReturnValue"/> is <see cref="CKR.CKR_OK"/>.
/// </para>
/// </remarks>
/// <param name="method">Name of the PKCS#11 function whose answers matched more than one token.</param>
/// <param name="message">Optional explanatory message.</param>
/// <param name="slotIds">The slots holding a matching token.</param>
public sealed class Pkcs11AmbiguousTokenException(string method, string? message, IReadOnlyList<SlotId> slotIds)
    : Pkcs11Exception(CKR.CKR_OK, method, message)
{
    /// <summary>The slots holding a matching token.</summary>
    public IReadOnlyList<SlotId> SlotIds { get; } = slotIds ?? [];
}
