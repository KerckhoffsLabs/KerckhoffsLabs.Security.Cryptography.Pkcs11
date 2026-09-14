using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// Shared exception filter for the AEAD wrappers' PKCS#11 v3.0 message-API attempt: some modules
/// export the message-mode entry points (<c>C_MessageEncryptInit</c> et al.) but do not implement a
/// given mechanism through them (e.g. opencryptoki for AES-GCM/CCM and ChaCha20-Poly1305),
/// returning <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/>. Use in a
/// <c>catch (Pkcs11Exception ex) when (Pkcs11MessageApiFallback.IsUnsupported(ex))</c> clause around
/// the message-API attempt: <c>C_Message[En|De]cryptInit</c> is always the first call, so nothing has
/// been written yet and falling through to the v2.40 classic-params path is side-effect-free.
/// </summary>
/// <remarks>
/// Not a <c>try</c>/<c>catch</c>-wrapping delegate helper: the message-API attempt takes and returns
/// <c>Span&lt;byte&gt;</c>/<c>ReadOnlySpan&lt;byte&gt;</c> parameters, which cannot be captured by a
/// lambda closure (CS9108) — the shared piece is this filter, not the control flow around it.
/// </remarks>
internal static class Pkcs11MessageApiFallback
{
    public static bool IsUnsupported(Pkcs11Exception ex) => ex.ReturnValue == CKR.CKR_FUNCTION_NOT_SUPPORTED;
}
