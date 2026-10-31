using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// The parameter scope of a call made on <see cref="Session"/>: what a key-valued mechanism parameter
/// needs to resolve its key to a handle in that session. The memory itself is owned by the Native
/// <see cref="MechanismParameterScope"/>.
/// </summary>
/// <param name="session">The session performing the call.</param>
internal sealed class SessionParameterScope(Pkcs11SessionCore session) : MechanismParameterScope
{
    /// <summary>The session performing the call.</summary>
    public Pkcs11SessionCore Session { get; } = session;

    /// <summary>
    /// The secure-default attributes the session appends to each additional derived key's template
    /// (SP 800-108 <c>CK_DERIVED_KEY</c>), in the order the keys were requested, after judging every
    /// one of those templates by the key-template policy. <see langword="null"/> when the call did
    /// not go through that check — marshalling additional derived keys in such a scope is refused.
    /// </summary>
    /// <remarks>
    /// Owned by the calling session method, which keeps the attributes alive until the native call
    /// returns and then disposes them; the scope only reads them.
    /// </remarks>
    public IReadOnlyList<IReadOnlyList<ObjectAttribute>>? AdditionalDerivedKeyDefaults { get; init; }
}
