using System.Diagnostics.CodeAnalysis;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

/// <summary>
/// Base type for exceptions raised in response to a non-CKR_OK return value from a
/// PKCS#11 native call.
/// </summary>
/// <remarks>
/// Carries the PKCS#11 method name that failed and the underlying CKR. Typed subclasses
/// (<c>Pkcs11AuthenticationException</c>, <c>Pkcs11SessionException</c>, etc.) categorize
/// related CKR values so callers can catch by category.
///
/// Use the appropriate static at each call site:
/// <list type="bullet">
///   <item><see cref="ThrowIfError(CKR, string)"/> — the normal guard-clause path; no-op on <c>CKR_OK</c>.</item>
///   <item><see cref="Throw(CKR, string)"/> — unconditional throw, marked <c>[DoesNotReturn]</c> for nullability flow analysis.</item>
///   <item><c>throw <see cref="Create(CKR, string)"/></c> — literal-throw form required where definite-assignment analysis (CS0177) needs the throw to be visible syntactically.</item>
/// </list>
/// Never construct instances directly.
/// </remarks>
/// <remarks>
/// Initializes a new instance carrying the CKR and method name. Used by
/// <see cref="ExceptionMapper"/> when dispatching <see cref="ThrowIfError(CKR, string)"/>.
/// </remarks>
/// <param name="returnValue">The PKCS#11 return value.</param>
/// <param name="method">Name of the failing PKCS#11 method.</param>
/// <param name="message">Optional explanatory message. When null, a default message
/// of the form <c>"PKCS#11 method &lt;method&gt; returned &lt;returnValue&gt;"</c> is used.</param>
public abstract class Pkcs11Exception(CKR returnValue, string method, string? message) : Exception(BuildMessage(method, returnValue, message))
{
    /// <summary>PKCS#11 return value that triggered this exception.</summary>
    public CKR ReturnValue { get; } = returnValue;

    /// <summary>Name of the PKCS#11 method whose return value triggered this exception.</summary>
    public string Method { get; } = method;

    private static string BuildMessage(string method, CKR returnValue, string? message)
    {
        ArgumentNullException.ThrowIfNull(method);
        return message ?? $"PKCS#11 method {method} returned {FormatReturnValue(returnValue)}";
    }

    // Vendor-defined and not-yet-known codes have no enum name; render them as hex (the form
    // vendor documentation uses) instead of Enum.ToString's bare decimal.
    private static string FormatReturnValue(CKR returnValue) => returnValue switch
    {
        _ when Enum.IsDefined(returnValue) => returnValue.ToString(),
        >= CKR.CKR_VENDOR_DEFINED => $"vendor-defined CKR 0x{(uint)returnValue:X8}",
        _ => $"unrecognized CKR 0x{(uint)returnValue:X8}",
    };

    /// <summary>
    /// Throws the appropriate typed <see cref="Pkcs11Exception"/> subclass when
    /// <paramref name="returnValue"/> is anything other than <see cref="CKR.CKR_OK"/>.
    /// Returns immediately on success.
    /// </summary>
    /// <param name="returnValue">The PKCS#11 return value to inspect.</param>
    /// <param name="method">Name of the PKCS#11 method that produced the value.</param>
    public static void ThrowIfError(CKR returnValue, string method)
    {
        if (returnValue != CKR.CKR_OK) Throw(returnValue, method);
    }

    /// <summary>
    /// Unconditionally throws the typed <see cref="Pkcs11Exception"/> subclass that
    /// categorizes <paramref name="returnValue"/>. Use this when there is no need to
    /// satisfy definite-assignment analysis for an <c>out</c> parameter on the
    /// non-throwing branches of the surrounding control flow. When such analysis is
    /// required (e.g., the fall-through branch of a tri-state if/else-if/else),
    /// prefer <c>throw <see cref="Create(CKR, string)"/></c> — the C# compiler honors
    /// only literal <c>throw</c> expressions for CS0177, not <c>[DoesNotReturn]</c>.
    /// </summary>
    /// <param name="returnValue">The PKCS#11 return value to dispatch.</param>
    /// <param name="method">Name of the PKCS#11 method that produced the value.</param>
    [DoesNotReturn]
    public static void Throw(CKR returnValue, string method)
        => throw ExceptionMapper.Map(returnValue, method);

    /// <summary>
    /// Builds (but does not throw) the typed <see cref="Pkcs11Exception"/> subclass that
    /// categorizes <paramref name="returnValue"/>. Use as the operand of a literal
    /// <c>throw</c> expression at call sites where definite-assignment analysis requires
    /// it — e.g., <c>throw Pkcs11Exception.Create(rv, "C_Verify");</c> in the
    /// fall-through branch of a tri-state if/else-if/else pattern.
    /// </summary>
    /// <param name="returnValue">The PKCS#11 return value to dispatch.</param>
    /// <param name="method">Name of the PKCS#11 method that produced the value.</param>
    /// <returns>The typed exception to throw.</returns>
    public static Pkcs11Exception Create(CKR returnValue, string method)
        => ExceptionMapper.Map(returnValue, method);
}
