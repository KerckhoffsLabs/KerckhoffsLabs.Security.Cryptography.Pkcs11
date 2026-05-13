using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Flags indicating capabilities and status of the device
/// </summary>
public class TokenFlags
{
    /// <summary>
    /// Bits flags indicating capabilities and status of the device
    /// </summary>
    protected NativeCULong _flags;

    /// <summary>
    /// Bits flags indicating capabilities and status of the device
    /// </summary>
    public ulong Flags
    {
        get
        {
            return (ulong)_flags;
        }
    }

    /// <summary>
    /// True if the token has its own random number generator
    /// </summary>
    public bool Rng
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_RNG.Value).Value == CKF.CKF_RNG.Value;
        }
    }

    /// <summary>
    /// True if the token is write-protected
    /// </summary>
    public bool WriteProtected
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_WRITE_PROTECTED.Value).Value == CKF.CKF_WRITE_PROTECTED.Value;
        }
    }

    /// <summary>
    /// True if there are some cryptographic functions that a user must be logged in to perform
    /// </summary>
    public bool LoginRequired
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_LOGIN_REQUIRED.Value).Value == CKF.CKF_LOGIN_REQUIRED.Value;
        }
    }

    /// <summary>
    /// True if the normal user's PIN has been initialized
    /// </summary>
    public bool UserPinInitialized
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_USER_PIN_INITIALIZED.Value).Value == CKF.CKF_USER_PIN_INITIALIZED.Value;
        }
    }

    /// <summary>
    /// True if a successful save of a session's cryptographic operations state always contains all keys needed to restore the state of the session
    /// </summary>
    public bool RestoreKeyNotNeeded
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_RESTORE_KEY_NOT_NEEDED.Value).Value == CKF.CKF_RESTORE_KEY_NOT_NEEDED.Value;
        }
    }

    /// <summary>
    /// True if token has its own hardware clock
    /// </summary>
    public bool ClockOnToken
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_CLOCK_ON_TOKEN.Value).Value == CKF.CKF_CLOCK_ON_TOKEN.Value;
        }
    }
    
    /// <summary>
    /// True if token has a "protected authentication path", whereby a user can log into the token without passing a PIN through the Cryptoki library
    /// </summary>
    public bool ProtectedAuthenticationPath
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_PROTECTED_AUTHENTICATION_PATH.Value).Value == CKF.CKF_PROTECTED_AUTHENTICATION_PATH.Value;
        }
    }

    /// <summary>
    /// True if a single session with the token can perform dual cryptographic operations
    /// </summary>
    public bool DualCryptoOperations
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_DUAL_CRYPTO_OPERATIONS.Value).Value == CKF.CKF_DUAL_CRYPTO_OPERATIONS.Value;
        }
    }

    /// <summary>
    /// True if the token has been initialized using C_InitializeToken or an equivalent mechanism
    /// </summary>
    public bool TokenInitialized
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_TOKEN_INITIALIZED.Value).Value == CKF.CKF_TOKEN_INITIALIZED.Value;
        }
    }

    /// <summary>
    /// True if the token supports secondary authentication for private key objects
    /// </summary>
    public bool SecondaryAuthentication
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_SECONDARY_AUTHENTICATION.Value).Value == CKF.CKF_SECONDARY_AUTHENTICATION.Value;
        }
    }

    /// <summary>
    /// True if an incorrect user login PIN has been entered at least once since the last successful authentication
    /// </summary>
    public bool UserPinCountLow
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_USER_PIN_COUNT_LOW.Value).Value == CKF.CKF_USER_PIN_COUNT_LOW.Value;
        }
    }

    /// <summary>
    /// True if supplying an incorrect user PIN will make it to become locked
    /// </summary>
    public bool UserPinFinalTry
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_USER_PIN_FINAL_TRY.Value).Value == CKF.CKF_USER_PIN_FINAL_TRY.Value;
        }
    }

    /// <summary>
    /// True if the user PIN has been locked. User login to the token is not possible.
    /// </summary>
    public bool UserPinLocked
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_USER_PIN_LOCKED.Value).Value == CKF.CKF_USER_PIN_LOCKED.Value;
        }
    }

    /// <summary>
    /// True if the user PIN value is the default value set by token initialization or manufacturing, or the PIN has been expired by the card
    /// </summary>
    public bool UserPinToBeChanged
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_USER_PIN_TO_BE_CHANGED.Value).Value == CKF.CKF_USER_PIN_TO_BE_CHANGED.Value;
        }
    }

    /// <summary>
    /// True if an incorrect SO login PIN has been entered at least once since the last successful authentication
    /// </summary>
    public bool SoPinCountLow
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_SO_PIN_COUNT_LOW.Value).Value == CKF.CKF_SO_PIN_COUNT_LOW.Value;
        }
    }

    /// <summary>
    /// True if supplying an incorrect SO PIN will make it to become locked.
    /// </summary>
    public bool SoPinFinalTry
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_SO_PIN_FINAL_TRY.Value).Value == CKF.CKF_SO_PIN_FINAL_TRY.Value;
        }
    }

    /// <summary>
    /// True if the SO PIN has been locked. User login to the token is not possible.
    /// </summary>
    public bool SoPinLocked
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_SO_PIN_LOCKED.Value).Value == CKF.CKF_SO_PIN_LOCKED.Value;
        }
    }

    /// <summary>
    /// True if the SO PIN value is the default value set by token initialization or manufacturing, or the PIN has been expired by the card.
    /// </summary>
    public bool SoPinToBeChanged
    {
        get
        {
            return new NativeCULong(_flags.Value & CKF.CKF_SO_PIN_TO_BE_CHANGED.Value).Value == CKF.CKF_SO_PIN_TO_BE_CHANGED.Value;
        }
    }

    /// <summary>
    /// Initializes new instance of TokenFlags class
    /// </summary>
    /// <param name="flags">Bits flags indicating capabilities and status of the device</param>
    protected internal TokenFlags(NativeCULong flags)
    {
        _flags = flags;
    }
}