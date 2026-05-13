using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Flags specifying mechanism capabilities.
/// </summary>
public sealed record MechanismFlags
{
    /// <summary>Bit flags specifying mechanism capabilities.</summary>
    public ulong Flags { get; }

    /// <summary>True if the mechanism is performed by the device; false if the mechanism is performed in software.</summary>
    public bool Hw
        => (Flags & CKF.CKF_HW.Value) == CKF.CKF_HW.Value;

    /// <summary>True if the mechanism can be used with C_EncryptInit.</summary>
    public bool Encrypt
        => (Flags & CKF.CKF_ENCRYPT.Value) == CKF.CKF_ENCRYPT.Value;

    /// <summary>True if the mechanism can be used with C_DecryptInit.</summary>
    public bool Decrypt
        => (Flags & CKF.CKF_DECRYPT.Value) == CKF.CKF_DECRYPT.Value;

    /// <summary>True if the mechanism can be used with C_DigestInit.</summary>
    public bool Digest
        => (Flags & CKF.CKF_DIGEST.Value) == CKF.CKF_DIGEST.Value;

    /// <summary>True if the mechanism can be used with C_SignInit.</summary>
    public bool Sign
        => (Flags & CKF.CKF_SIGN.Value) == CKF.CKF_SIGN.Value;

    /// <summary>True if the mechanism can be used with C_SignRecoverInit.</summary>
    public bool SignRecover
        => (Flags & CKF.CKF_SIGN_RECOVER.Value) == CKF.CKF_SIGN_RECOVER.Value;

    /// <summary>True if the mechanism can be used with C_VerifyInit.</summary>
    public bool Verify
        => (Flags & CKF.CKF_VERIFY.Value) == CKF.CKF_VERIFY.Value;

    /// <summary>True if the mechanism can be used with C_VerifyRecoverInit.</summary>
    public bool VerifyRecover
        => (Flags & CKF.CKF_VERIFY_RECOVER.Value) == CKF.CKF_VERIFY_RECOVER.Value;

    /// <summary>True if the mechanism can be used with C_GenerateKey.</summary>
    public bool Generate
        => (Flags & CKF.CKF_GENERATE.Value) == CKF.CKF_GENERATE.Value;

    /// <summary>True if the mechanism can be used with C_GenerateKeyPair.</summary>
    public bool GenerateKeyPair
        => (Flags & CKF.CKF_GENERATE_KEY_PAIR.Value) == CKF.CKF_GENERATE_KEY_PAIR.Value;

    /// <summary>True if the mechanism can be used with C_WrapKey.</summary>
    public bool Wrap
        => (Flags & CKF.CKF_WRAP.Value) == CKF.CKF_WRAP.Value;

    /// <summary>True if the mechanism can be used with C_UnwrapKey.</summary>
    public bool Unwrap
        => (Flags & CKF.CKF_UNWRAP.Value) == CKF.CKF_UNWRAP.Value;

    /// <summary>True if the mechanism can be used with C_DeriveKey.</summary>
    public bool Derive
        => (Flags & CKF.CKF_DERIVE.Value) == CKF.CKF_DERIVE.Value;

    /// <summary>True if there is an extension to the flags; false if no extensions.</summary>
    public bool Extension
        => (Flags & CKF.CKF_EXTENSION.Value) == CKF.CKF_EXTENSION.Value;

    /// <summary>True if the mechanism can be used with EC domain parameters over Fp.</summary>
    public bool EcFp
        => (Flags & CKF.CKF_EC_F_P.Value) == CKF.CKF_EC_F_P.Value;

    /// <summary>True if the mechanism can be used with EC domain parameters over F2m.</summary>
    public bool EcF2m
        => (Flags & CKF.CKF_EC_F_2M.Value) == CKF.CKF_EC_F_2M.Value;

    /// <summary>True if the mechanism can be used with EC domain parameters of the choice ecParameters.</summary>
    public bool EcEcParameters
        => (Flags & CKF.CKF_EC_ECPARAMETERS.Value) == CKF.CKF_EC_ECPARAMETERS.Value;

    /// <summary>True if the mechanism can be used with EC domain parameters of the choice namedCurve.</summary>
    public bool EcNamedCurve
        => (Flags & CKF.CKF_EC_NAMEDCURVE.Value) == CKF.CKF_EC_NAMEDCURVE.Value;

    /// <summary>True if the mechanism can be used with elliptic curve point uncompressed.</summary>
    public bool EcUncompress
        => (Flags & CKF.CKF_EC_UNCOMPRESS.Value) == CKF.CKF_EC_UNCOMPRESS.Value;

    /// <summary>True if the mechanism can be used with elliptic curve point compressed.</summary>
    public bool EcCompress
        => (Flags & CKF.CKF_EC_COMPRESS.Value) == CKF.CKF_EC_COMPRESS.Value;

    internal MechanismFlags(NativeCULong flags) => Flags = (ulong)flags;
}
