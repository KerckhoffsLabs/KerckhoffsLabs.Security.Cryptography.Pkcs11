namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

/// <summary>
/// One entry in a restrictive policy's mechanism allow-list: which operations it approves outright,
/// which it approves only for SP 800-131A "legacy use" (verifying an old signature, decrypting data
/// wrapped under a deprecated cipher, …), an optional check on the mechanism's parameters, and why it
/// is allowed at all.
/// </summary>
/// <param name="Operations">Operations approved without restriction.</param>
/// <param name="LegacyOperations">
/// Operations approved only for legacy use; <see cref="CryptoOperations.None"/> when the mechanism has
/// no legacy carve-out. Disjoint in practice from <paramref name="Operations"/>, though the evaluator
/// does not require it.
/// </param>
/// <param name="ParameterCheck">
/// Validates the mechanism's parameters (an OAEP/PSS hash, a PQC pre-hash, …) once the operation itself
/// is approved; <see langword="null"/> when the mechanism type alone decides. Its denial, when it
/// denies, is returned as-is.
/// </param>
/// <param name="Rationale">Why the mechanism is allowed — for <c>NistApproved</c>, the NIST publication citation.</param>
internal sealed record MechanismRule(
    CryptoOperations Operations,
    CryptoOperations LegacyOperations,
    MechanismCheck? ParameterCheck,
    string Rationale);
