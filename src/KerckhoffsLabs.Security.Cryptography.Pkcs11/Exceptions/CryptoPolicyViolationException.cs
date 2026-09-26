using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

/// <summary>
/// Thrown when the workspace's <see cref="ICryptoPolicy"/> refuses an operation, or when the library
/// refuses an operation on security grounds regardless of policy (for example, exporting private key
/// material from a PKCS#11 key).
/// </summary>
/// <remarks>
/// Derives from <see cref="CryptographicException"/> so a caller handling failures from the BCL-shaped
/// façades in the usual way still catches it.
/// </remarks>
public sealed class CryptoPolicyViolationException : CryptographicException
{
    /// <summary>Name of the policy that refused, or <see langword="null"/> for a policy-independent refusal.</summary>
    public string? PolicyName { get; }

    /// <summary>The refused request, or <see langword="null"/> for a policy-independent refusal.</summary>
    public PolicyRequest? Request { get; }

    /// <summary>The policy's reason, or <see langword="null"/> for a policy-independent refusal.</summary>
    public string? Reason { get; }

    /// <summary>The mechanism involved, when there is one.</summary>
    public CKM? Mechanism { get; }

    /// <summary>Creates the exception for a policy denial.</summary>
    /// <param name="policyName">The refusing policy's <see cref="ICryptoPolicy.Name"/>.</param>
    /// <param name="request">The refused request.</param>
    /// <param name="reason">The policy's reason.</param>
    /// <exception cref="ArgumentNullException"><paramref name="policyName"/>, <paramref name="request"/> or <paramref name="reason"/> is null.</exception>
    public CryptoPolicyViolationException(string policyName, PolicyRequest request, string reason)
        : base(FormatMessage(policyName, request, reason))
    {
        PolicyName = policyName;
        Request = request;
        Reason = reason;
        Mechanism = request.MechanismType;
    }

    // Validates before the base constructor runs: the message needs request.Describe().
    private static string FormatMessage(string policyName, PolicyRequest request, string reason)
    {
        ArgumentNullException.ThrowIfNull(policyName);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(reason);
        return $"{policyName} policy refused {request.Describe()}: {reason}";
    }

    /// <summary>Creates the exception for a policy-independent refusal.</summary>
    /// <param name="message">Why the operation was refused.</param>
    public CryptoPolicyViolationException(string message)
        : base(message)
    {
    }
}
