using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Flags indicating capabilities and status of the device.
/// </summary>
public sealed record TokenFlags
{
    /// <summary>Bit flags indicating capabilities and status of the device.</summary>
    public ulong Flags { get; }

    /// <summary>True if the token has its own random number generator.</summary>
    public bool Rng
        => (Flags & CKF.CKF_RNG.Value) == CKF.CKF_RNG.Value;

    /// <summary>True if the token is write-protected.</summary>
    public bool WriteProtected
        => (Flags & CKF.CKF_WRITE_PROTECTED.Value) == CKF.CKF_WRITE_PROTECTED.Value;

    /// <summary>True if there are some cryptographic functions that a user must be logged in to perform.</summary>
    public bool LoginRequired
        => (Flags & CKF.CKF_LOGIN_REQUIRED.Value) == CKF.CKF_LOGIN_REQUIRED.Value;

    /// <summary>True if the normal user's PIN has been initialized.</summary>
    public bool UserPinInitialized
        => (Flags & CKF.CKF_USER_PIN_INITIALIZED.Value) == CKF.CKF_USER_PIN_INITIALIZED.Value;

    /// <summary>True if a successful save of a session's cryptographic operations state always contains all keys needed to restore the state of the session.</summary>
    public bool RestoreKeyNotNeeded
        => (Flags & CKF.CKF_RESTORE_KEY_NOT_NEEDED.Value) == CKF.CKF_RESTORE_KEY_NOT_NEEDED.Value;

    /// <summary>True if token has its own hardware clock.</summary>
    public bool ClockOnToken
        => (Flags & CKF.CKF_CLOCK_ON_TOKEN.Value) == CKF.CKF_CLOCK_ON_TOKEN.Value;

    /// <summary>True if token has a "protected authentication path", whereby a user can log into the token without passing a PIN through the Cryptoki library.</summary>
    public bool ProtectedAuthenticationPath
        => (Flags & CKF.CKF_PROTECTED_AUTHENTICATION_PATH.Value) == CKF.CKF_PROTECTED_AUTHENTICATION_PATH.Value;

    /// <summary>True if a single session with the token can perform dual cryptographic operations.</summary>
    public bool DualCryptoOperations
        => (Flags & CKF.CKF_DUAL_CRYPTO_OPERATIONS.Value) == CKF.CKF_DUAL_CRYPTO_OPERATIONS.Value;

    /// <summary>True if the token has been initialized using C_InitializeToken or an equivalent mechanism.</summary>
    public bool TokenInitialized
        => (Flags & CKF.CKF_TOKEN_INITIALIZED.Value) == CKF.CKF_TOKEN_INITIALIZED.Value;

    /// <summary>True if the token supports secondary authentication for private key objects.</summary>
    public bool SecondaryAuthentication
        => (Flags & CKF.CKF_SECONDARY_AUTHENTICATION.Value) == CKF.CKF_SECONDARY_AUTHENTICATION.Value;

    /// <summary>True if an incorrect user login PIN has been entered at least once since the last successful authentication.</summary>
    public bool UserPinCountLow
        => (Flags & CKF.CKF_USER_PIN_COUNT_LOW.Value) == CKF.CKF_USER_PIN_COUNT_LOW.Value;

    /// <summary>True if supplying an incorrect user PIN will make it to become locked.</summary>
    public bool UserPinFinalTry
        => (Flags & CKF.CKF_USER_PIN_FINAL_TRY.Value) == CKF.CKF_USER_PIN_FINAL_TRY.Value;

    /// <summary>True if the user PIN has been locked. User login to the token is not possible.</summary>
    public bool UserPinLocked
        => (Flags & CKF.CKF_USER_PIN_LOCKED.Value) == CKF.CKF_USER_PIN_LOCKED.Value;

    /// <summary>True if the user PIN value is the default value set by token initialization or manufacturing, or the PIN has been expired by the card.</summary>
    public bool UserPinToBeChanged
        => (Flags & CKF.CKF_USER_PIN_TO_BE_CHANGED.Value) == CKF.CKF_USER_PIN_TO_BE_CHANGED.Value;

    /// <summary>True if an incorrect SO login PIN has been entered at least once since the last successful authentication.</summary>
    public bool SoPinCountLow
        => (Flags & CKF.CKF_SO_PIN_COUNT_LOW.Value) == CKF.CKF_SO_PIN_COUNT_LOW.Value;

    /// <summary>True if supplying an incorrect SO PIN will make it to become locked.</summary>
    public bool SoPinFinalTry
        => (Flags & CKF.CKF_SO_PIN_FINAL_TRY.Value) == CKF.CKF_SO_PIN_FINAL_TRY.Value;

    /// <summary>True if the SO PIN has been locked. User login to the token is not possible.</summary>
    public bool SoPinLocked
        => (Flags & CKF.CKF_SO_PIN_LOCKED.Value) == CKF.CKF_SO_PIN_LOCKED.Value;

    /// <summary>True if the SO PIN value is the default value set by token initialization or manufacturing, or the PIN has been expired by the card.</summary>
    public bool SoPinToBeChanged
        => (Flags & CKF.CKF_SO_PIN_TO_BE_CHANGED.Value) == CKF.CKF_SO_PIN_TO_BE_CHANGED.Value;

    /// <summary>True if the token's RNG must be seeded (or re-seeded) via C_SeedRandom before use (PKCS#11 v3.0).</summary>
    public bool SeedRandomRequired
        => (Flags & CKF.CKF_SEED_RANDOM_REQUIRED.Value) == CKF.CKF_SEED_RANDOM_REQUIRED.Value;

    internal TokenFlags(NativeCULong flags) => Flags = (ulong)flags;
}
