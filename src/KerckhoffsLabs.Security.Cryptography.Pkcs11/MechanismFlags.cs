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
        => (Flags & CKF.CKF_HW) == CKF.CKF_HW;

    /// <summary>True if the mechanism can be used with C_EncryptInit.</summary>
    public bool Encrypt
        => (Flags & CKF.CKF_ENCRYPT) == CKF.CKF_ENCRYPT;

    /// <summary>True if the mechanism can be used with C_DecryptInit.</summary>
    public bool Decrypt
        => (Flags & CKF.CKF_DECRYPT) == CKF.CKF_DECRYPT;

    /// <summary>True if the mechanism can be used with C_DigestInit.</summary>
    public bool Digest
        => (Flags & CKF.CKF_DIGEST) == CKF.CKF_DIGEST;

    /// <summary>True if the mechanism can be used with C_SignInit.</summary>
    public bool Sign
        => (Flags & CKF.CKF_SIGN) == CKF.CKF_SIGN;

    /// <summary>True if the mechanism can be used with C_SignRecoverInit.</summary>
    public bool SignRecover
        => (Flags & CKF.CKF_SIGN_RECOVER) == CKF.CKF_SIGN_RECOVER;

    /// <summary>True if the mechanism can be used with C_VerifyInit.</summary>
    public bool Verify
        => (Flags & CKF.CKF_VERIFY) == CKF.CKF_VERIFY;

    /// <summary>True if the mechanism can be used with C_VerifyRecoverInit.</summary>
    public bool VerifyRecover
        => (Flags & CKF.CKF_VERIFY_RECOVER) == CKF.CKF_VERIFY_RECOVER;

    /// <summary>True if the mechanism can be used with C_GenerateKey.</summary>
    public bool Generate
        => (Flags & CKF.CKF_GENERATE) == CKF.CKF_GENERATE;

    /// <summary>True if the mechanism can be used with C_GenerateKeyPair.</summary>
    public bool GenerateKeyPair
        => (Flags & CKF.CKF_GENERATE_KEY_PAIR) == CKF.CKF_GENERATE_KEY_PAIR;

    /// <summary>True if the mechanism can be used with C_WrapKey.</summary>
    public bool Wrap
        => (Flags & CKF.CKF_WRAP) == CKF.CKF_WRAP;

    /// <summary>True if the mechanism can be used with C_UnwrapKey.</summary>
    public bool Unwrap
        => (Flags & CKF.CKF_UNWRAP) == CKF.CKF_UNWRAP;

    /// <summary>True if the mechanism can be used with C_DeriveKey.</summary>
    public bool Derive
        => (Flags & CKF.CKF_DERIVE) == CKF.CKF_DERIVE;

    /// <summary>True if there is an extension to the flags; false if no extensions.</summary>
    public bool Extension
        => (Flags & CKF.CKF_EXTENSION) == CKF.CKF_EXTENSION;

    /// <summary>True if the mechanism can be used with EC domain parameters over Fp.</summary>
    public bool EcFp
        => (Flags & CKF.CKF_EC_F_P) == CKF.CKF_EC_F_P;

    /// <summary>True if the mechanism can be used with EC domain parameters over F2m.</summary>
    public bool EcF2m
        => (Flags & CKF.CKF_EC_F_2M) == CKF.CKF_EC_F_2M;

    /// <summary>True if the mechanism can be used with EC domain parameters of the choice ecParameters.</summary>
    public bool EcEcParameters
        => (Flags & CKF.CKF_EC_ECPARAMETERS) == CKF.CKF_EC_ECPARAMETERS;

    /// <summary>True if the mechanism can be used with EC domain parameters of the choice namedCurve.</summary>
    public bool EcNamedCurve
        => (Flags & CKF.CKF_EC_NAMEDCURVE) == CKF.CKF_EC_NAMEDCURVE;

    /// <summary>True if the mechanism can be used with elliptic curve point uncompressed.</summary>
    public bool EcUncompress
        => (Flags & CKF.CKF_EC_UNCOMPRESS) == CKF.CKF_EC_UNCOMPRESS;

    /// <summary>True if the mechanism can be used with elliptic curve point compressed.</summary>
    public bool EcCompress
        => (Flags & CKF.CKF_EC_COMPRESS) == CKF.CKF_EC_COMPRESS;

    /// <summary>True if the mechanism accepts/returns the EC curve as an OID (PKCS#11 v3.0).</summary>
    public bool EcOid
        => (Flags & CKF.CKF_EC_OID) == CKF.CKF_EC_OID;

    /// <summary>True if the mechanism accepts/returns the EC curve as a printable name (PKCS#11 v3.0).</summary>
    public bool EcCurveName
        => (Flags & CKF.CKF_EC_CURVENAME) == CKF.CKF_EC_CURVENAME;

    /// <summary>True if the mechanism supports the message-based encrypt API (C_EncryptMessage) (PKCS#11 v3.0).</summary>
    public bool MessageEncrypt
        => (Flags & CKF.CKF_MESSAGE_ENCRYPT) == CKF.CKF_MESSAGE_ENCRYPT;

    /// <summary>True if the mechanism supports the message-based decrypt API (C_DecryptMessage) (PKCS#11 v3.0).</summary>
    public bool MessageDecrypt
        => (Flags & CKF.CKF_MESSAGE_DECRYPT) == CKF.CKF_MESSAGE_DECRYPT;

    /// <summary>True if the mechanism supports the message-based sign API (C_SignMessage) (PKCS#11 v3.0).</summary>
    public bool MessageSign
        => (Flags & CKF.CKF_MESSAGE_SIGN) == CKF.CKF_MESSAGE_SIGN;

    /// <summary>True if the mechanism supports the message-based verify API (C_VerifyMessage) (PKCS#11 v3.0).</summary>
    public bool MessageVerify
        => (Flags & CKF.CKF_MESSAGE_VERIFY) == CKF.CKF_MESSAGE_VERIFY;

    /// <summary>True if the mechanism supports processing multiple messages in a single operation (PKCS#11 v3.0).</summary>
    public bool MultiMessage
        => (Flags & CKF.CKF_MULTI_MESSAGE) == CKF.CKF_MULTI_MESSAGE;

    internal MechanismFlags(ulong flags) => Flags = flags;
}
