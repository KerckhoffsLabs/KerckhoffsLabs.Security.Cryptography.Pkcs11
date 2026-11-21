namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// A session's own policy under a library policy that allows no override (<see cref="Pkcs11LibraryOptions.Policy"/>):
/// a request goes ahead only if both allow it, the library's policy asked first. Allows no override either.
/// </summary>
internal sealed class CeilingCryptoPolicy : ICryptoPolicy
{
    private readonly ICryptoPolicy _ceiling;
    private readonly ICryptoPolicy _session;

    internal CeilingCryptoPolicy(ICryptoPolicy ceiling, ICryptoPolicy session)
    {
        ArgumentNullException.ThrowIfNull(ceiling);
        ArgumentNullException.ThrowIfNull(session);
        _ceiling = ceiling;
        _session = session;
        Name = $"{session.Name} within {ceiling.Name}";
    }

    /// <inheritdoc/>
    public string Name { get; }

    /// <inheritdoc/>
    /// <remarks>Always <see langword="false"/>: the ceiling allows none.</remarks>
    public bool AllowsOverride => false;

    /// <inheritdoc/>
    public PolicyDecision Evaluate(PolicyRequest request)
    {
        PolicyDecision library = _ceiling.Evaluate(request);
        if (!library.IsAllowed)
            return PolicyDecision.Deny($"{library.Reason} (the library's {_ceiling.Name} policy)");
        return _session.Evaluate(request);
    }
}
