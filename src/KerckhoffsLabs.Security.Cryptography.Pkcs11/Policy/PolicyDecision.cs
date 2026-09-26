namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>The verdict an <see cref="ICryptoPolicy"/> returns for one <see cref="PolicyRequest"/>.</summary>
/// <remarks>
/// <c>default(PolicyDecision)</c> is a <b>denial</b>, so a policy that forgets to return a verdict
/// fails closed.
/// </remarks>
public readonly record struct PolicyDecision
{
    private const string NoDecision = "The policy returned no decision.";

    private readonly bool _allowed;
    private readonly string? _reason;

    private PolicyDecision(bool allowed, string? reason)
    {
        _allowed = allowed;
        _reason = reason;
    }

    /// <summary><see langword="true"/> when the operation may proceed.</summary>
    public bool IsAllowed => _allowed;

    /// <summary>Why the operation was refused; <see langword="null"/> when allowed.</summary>
    public string? Reason => _allowed ? null : _reason ?? NoDecision;

    /// <summary>The operation may proceed.</summary>
    public static PolicyDecision Allow { get; } = new(true, null);

    /// <summary>The operation is refused.</summary>
    /// <param name="reason">Why, and ideally what to use instead. Must not contain secret material.</param>
    /// <returns>A denial.</returns>
    /// <exception cref="ArgumentException"><paramref name="reason"/> is null, empty, or whitespace.</exception>
    public static PolicyDecision Deny(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return new(false, reason);
    }
}
