using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// The parameter scope of a call made on <see cref="Session"/>: what a key-valued mechanism parameter
/// needs to resolve its key to a handle in that session. The memory itself is owned by the Native
/// <see cref="MechanismParameterScope"/>.
/// </summary>
/// <param name="session">The session performing the call.</param>
internal sealed class SessionParameterScope(Pkcs11Session session) : MechanismParameterScope
{
    /// <summary>The session performing the call.</summary>
    public Pkcs11Session Session { get; } = session;
}
