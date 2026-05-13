namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Thrown when an operation uses a mechanism the library considers insecure by default,
/// unless the caller has opted in via <c>Session.AllowInsecure = true</c>. Covers RSA
/// PKCS#1 v1.5 padding (for both encryption and signature), MD5 and SHA-1 (raw and in RSA
/// signature contexts), DES/3DES (encryption and MAC), and AES-ECB.
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

    /// <summary>
    /// Initializes a new <see cref="InsecureOperationException"/> for operation-level security
    /// refusals that are not tied to a specific PKCS#11 mechanism (e.g. refusing to export
    /// private key material from a non-extractable key).
    /// </summary>
    /// <param name="message">Human-readable explanation of why the operation was refused.</param>
    public InsecureOperationException(string message)
        : base(message)
    {
    }
}
