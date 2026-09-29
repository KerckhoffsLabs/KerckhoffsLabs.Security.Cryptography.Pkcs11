namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>The direction or kind of a cryptographic operation, as seen by an <see cref="ICryptoPolicy"/>.</summary>
/// <remarks>
/// Some policies are direction-sensitive — NIST SP 800-131A, for example, allows verifying a legacy
/// signature it no longer allows creating.
/// </remarks>
public enum CryptoOperation
{
    /// <summary><c>C_EncryptInit</c> / <c>C_MessageEncryptInit</c>.</summary>
    Encrypt,
    /// <summary><c>C_DecryptInit</c> / <c>C_MessageDecryptInit</c>.</summary>
    Decrypt,
    /// <summary><c>C_SignInit</c> (signatures and MACs).</summary>
    Sign,
    /// <summary><c>C_VerifyInit</c>, <c>C_VerifyRecoverInit</c>, <c>C_VerifySignatureInit</c>.</summary>
    Verify,
    /// <summary><c>C_WrapKey</c> / <c>C_WrapKeyAuthenticated</c>.</summary>
    Wrap,
    /// <summary><c>C_UnwrapKey</c> / <c>C_UnwrapKeyAuthenticated</c>.</summary>
    Unwrap,
    /// <summary><c>C_DeriveKey</c>.</summary>
    Derive,
    /// <summary><c>C_DigestInit</c>.</summary>
    Digest,
    /// <summary><c>C_GenerateKey</c>.</summary>
    GenerateKey,
    /// <summary><c>C_GenerateKeyPair</c>.</summary>
    GenerateKeyPair,
    /// <summary><c>C_EncapsulateKey</c>.</summary>
    Encapsulate,
    /// <summary><c>C_DecapsulateKey</c>.</summary>
    Decapsulate,
}
