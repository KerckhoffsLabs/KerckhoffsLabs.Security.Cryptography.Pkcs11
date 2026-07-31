namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// A parameter block that has already been laid out and written into the call's scope, rather than a
/// <c>[PackedForPkcs11]</c> struct waiting to be marshalled.
/// </summary>
/// <remarks>
/// <see cref="Mechanism.Marshal"/> normally receives an interop struct and marshals it, which relies
/// on the generator-emitted dispatch table and therefore only works for types compiled into this
/// assembly. A vendor parameter block has no such struct — <see cref="Pkcs11ParameterWriter"/>
/// produced its bytes directly — so it is handed over pre-marshalled instead.
/// </remarks>
/// <param name="Pointer">Address of the block, owned by the call's scope.</param>
/// <param name="Length">Length of the block in bytes.</param>
internal sealed record Pkcs11ParameterBlock(IntPtr Pointer, int Length);
