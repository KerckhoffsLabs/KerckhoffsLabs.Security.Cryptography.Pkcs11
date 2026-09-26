namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// Decides whether a cryptographic operation may proceed. A workspace is opened under exactly one
/// policy (see <see cref="CryptoPolicy"/> for the built-ins); every security-relevant operation is
/// described as a <see cref="PolicyRequest"/> and evaluated before anything reaches the token.
/// </summary>
/// <remarks>
/// <para>
/// Implementations must be side-effect free and thread-safe: the same instance may be shared by many
/// workspaces. Throwing from <see cref="Evaluate"/> aborts the operation with that exception.
/// </para>
/// <para>
/// <see cref="PolicyRequest"/> is a closed hierarchy that later library versions may extend. End every
/// <c>switch</c> over it with an arm that returns <see cref="PolicyDecision.Deny(string)"/>, so a request
/// kind your policy has never seen is refused rather than silently allowed.
/// </para>
/// </remarks>
public interface ICryptoPolicy
{
    /// <summary>Stable, human-readable name. Appears in logs and exception messages.</summary>
    string Name { get; }

    /// <summary>
    /// When <see langword="false"/>, a workspace opened under this policy refuses every
    /// <c>UsePolicy</c> lease, so the policy holds for the workspace's whole lifetime.
    /// </summary>
    bool AllowsOverride { get; }

    /// <summary>Evaluates one request.</summary>
    /// <param name="request">The operation being attempted.</param>
    /// <returns><see cref="PolicyDecision.Allow"/>, or a denial carrying the reason.</returns>
    PolicyDecision Evaluate(PolicyRequest request);
}
