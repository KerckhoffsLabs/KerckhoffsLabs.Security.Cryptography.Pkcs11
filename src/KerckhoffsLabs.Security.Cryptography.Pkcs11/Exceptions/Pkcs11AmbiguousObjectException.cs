using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

/// <summary>
/// Raised when a lookup that must identify exactly one object — such as
/// <see cref="Pkcs11Workspace.OpenKey(string, CKO?)"/> — matched more than one.
/// </summary>
/// <remarks>
/// <para>
/// Picking one of several matches would let whoever can create objects on the token decide which
/// key an operation uses, so the lookup refuses instead. Narrow it — by key class, or by
/// <c>CKA_ID</c> rather than label — or enumerate the candidates with
/// <see cref="Pkcs11Workspace.FindKeys"/> and choose explicitly.
/// </para>
/// <para>
/// This is the one <see cref="Pkcs11ObjectException"/> the library raises itself rather than
/// relaying from the module: every call succeeded, so <see cref="Pkcs11Exception.ReturnValue"/> is
/// <see cref="CKR.CKR_OK"/> and <see cref="Pkcs11Exception.Method"/> names the search that returned
/// too many objects.
/// </para>
/// </remarks>
/// <param name="method">Name of the PKCS#11 search that returned more than one object.</param>
/// <param name="message">Optional explanatory message.</param>
public sealed class Pkcs11AmbiguousObjectException(string method, string? message)
    : Pkcs11ObjectException(CKR.CKR_OK, method, message);
