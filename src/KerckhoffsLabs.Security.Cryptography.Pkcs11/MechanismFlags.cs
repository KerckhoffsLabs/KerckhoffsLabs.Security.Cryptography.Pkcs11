using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Flags specifying mechanism capabilities
/// </summary>
public class MechanismFlags
{
    /// <summary>
    /// Bits flags specifying mechanism capabilities
    /// </summary>
    protected NativeCULong _flags;

    /// <summary>
    /// Bits flags specifying mechanism capabilities
    /// </summary>
    public ulong Flags
    {
        get
        {
            return (ulong)_flags;
        }
    }

    /// <summary>
    /// True if the mechanism is performed by the device; false if the mechanism is performed in software
    /// </summary>
    public bool Hw
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_HW.Value).Value == CKF.CKF_HW.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with C_EncryptInit
    /// </summary>
    public bool Encrypt
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_ENCRYPT.Value).Value == CKF.CKF_ENCRYPT.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with C_DecryptInit
    /// </summary>
    public bool Decrypt
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_DECRYPT.Value).Value == CKF.CKF_DECRYPT.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with C_DigestInit
    /// </summary>
    public bool Digest
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_DIGEST.Value).Value == CKF.CKF_DIGEST.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with C_SignInit
    /// </summary>
    public bool Sign
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_SIGN.Value).Value == CKF.CKF_SIGN.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with C_SignRecoverInit
    /// </summary>
    public bool SignRecover
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_SIGN_RECOVER.Value).Value == CKF.CKF_SIGN_RECOVER.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with C_VerifyInit
    /// </summary>
    public bool Verify
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_VERIFY.Value).Value == CKF.CKF_VERIFY.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with C_VerifyRecoverInit
    /// </summary>
    public bool VerifyRecover
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_VERIFY_RECOVER.Value).Value == CKF.CKF_VERIFY_RECOVER.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with C_GenerateKey
    /// </summary>
    public bool Generate
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_GENERATE.Value).Value == CKF.CKF_GENERATE.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with C_GenerateKeyPair
    /// </summary>
    public bool GenerateKeyPair
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_GENERATE_KEY_PAIR.Value).Value == CKF.CKF_GENERATE_KEY_PAIR.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with C_WrapKey
    /// </summary>
    public bool Wrap
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_WRAP.Value).Value == CKF.CKF_WRAP.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with C_UnwrapKey
    /// </summary>
    public bool Unwrap
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_UNWRAP.Value).Value == CKF.CKF_UNWRAP.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with C_DeriveKey
    /// </summary>
    public bool Derive
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_DERIVE.Value).Value == CKF.CKF_DERIVE.Value;
        }
    }

    /// <summary>
    /// True if there is an extension to the flags; false if no extensions.
    /// </summary>
    public bool Extension
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_EXTENSION.Value).Value == CKF.CKF_EXTENSION.Value;
        }
    }

    #region Elliptic Curve

    /// <summary>
    /// True if the mechanism can be used with EC domain parameters over Fp
    /// </summary>
    public bool EcFp
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_EC_F_P.Value).Value == CKF.CKF_EC_F_P.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with EC domain parameters over F2m
    /// </summary>
    public bool EcF2m
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_EC_F_2M.Value).Value == CKF.CKF_EC_F_2M.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with EC domain parameters of the choice ecParameters
    /// </summary>
    public bool EcEcParameters
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_EC_ECPARAMETERS.Value).Value == CKF.CKF_EC_ECPARAMETERS.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with EC domain parameters of the choice namedCurve
    /// </summary>
    public bool EcNamedCurve
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_EC_NAMEDCURVE.Value).Value == CKF.CKF_EC_NAMEDCURVE.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with elliptic curve point uncompressed
    /// </summary>
    public bool EcUncompress
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_EC_UNCOMPRESS.Value).Value == CKF.CKF_EC_UNCOMPRESS.Value;
        }
    }

    /// <summary>
    /// True if the mechanism can be used with elliptic curve point compressed
    /// </summary>
    public bool EcCompress
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_EC_COMPRESS.Value).Value == CKF.CKF_EC_COMPRESS.Value;
        }
    }

    #endregion

    /// <summary>
    /// Initializes new instance of MechanismFlags class
    /// </summary>
    /// <param name="flags">Bits flags specifying mechanism capabilities</param>
    protected internal MechanismFlags(NativeCULong flags)
    {
        _flags = flags;
    }
}