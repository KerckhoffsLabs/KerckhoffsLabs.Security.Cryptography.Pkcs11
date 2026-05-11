namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Thrown when an operation uses a mechanism the library considers insecure by default,
/// unless the caller has opted in via <c>Session.AllowInsecure = true</c>. Covers RSA
/// PKCS#1 v1.5 padding, DES/3DES, AES-ECB, MD5/SHA-1 in signature contexts, and other
/// mechanisms flagged in the parent design spec.
/// </summary>
public sealed class InsecureOperationException : Exception
{
    /// <summary>The mechanism that triggered the gate.</summary>
    public CKM Mechanism { get; }

    /// <summary>
    /// Initializes a new <see cref="InsecureOperationException"/>.
    /// </summary>
    /// <param name="mechanism">The mechanism that was rejected.</param>
    /// <param name="suggestion">A short pointer to the modern alternative, included in the message.</param>
    public InsecureOperationException(CKM mechanism, string suggestion)
        : base($"Mechanism {mechanism} is disallowed by default. {suggestion} " +
               $"To bypass, set Session.AllowInsecure = true before invoking the operation.")
    {
        Mechanism = mechanism;
    }
}
