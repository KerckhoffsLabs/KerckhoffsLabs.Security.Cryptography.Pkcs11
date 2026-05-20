namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Bit flags
/// </summary>
public static class CKF
{
    /// <summary>
    /// True if a token is present in the slot
    /// </summary>
    public static readonly NativeCULong CKF_TOKEN_PRESENT = new(0x00000001);

    /// <summary>
    /// True if the reader supports removable devices
    /// </summary>
    public static readonly NativeCULong CKF_REMOVABLE_DEVICE = new(0x00000002);

    /// <summary>
    /// True if the slot is a hardware slot, as opposed to a software slot implementing a "soft token"
    /// </summary>
    public static readonly NativeCULong CKF_HW_SLOT = new(0x00000004);

    /// <summary>
    /// True if the token has its own random number generator
    /// </summary>
    public static readonly NativeCULong CKF_RNG = new(0x00000001);

    /// <summary>
    /// True if the token is write-protected
    /// </summary>
    public static readonly NativeCULong CKF_WRITE_PROTECTED = new(0x00000002);

    /// <summary>
    /// True if there are some cryptographic functions that a user must be logged in to perform
    /// </summary>
    public static readonly NativeCULong CKF_LOGIN_REQUIRED = new(0x00000004);

    /// <summary>
    /// True if the normal user's PIN has been initialized
    /// </summary>
    public static readonly NativeCULong CKF_USER_PIN_INITIALIZED = new(0x00000008);

    /// <summary>
    /// True if a successful save of a session's cryptographic operations state always contains all keys needed to restore the state of the session
    /// </summary>
    public static readonly NativeCULong CKF_RESTORE_KEY_NOT_NEEDED = new(0x00000020);

    /// <summary>
    /// True if token has its own hardware clock
    /// </summary>
    public static readonly NativeCULong CKF_CLOCK_ON_TOKEN = new(0x00000040);

    /// <summary>
    /// True if token has a "protected authentication path", whereby a user can log into the token without passing a PIN through the Cryptoki library
    /// </summary>
    public static readonly NativeCULong CKF_PROTECTED_AUTHENTICATION_PATH = new(0x00000100);

    /// <summary>
    /// True if a single session with the token can perform dual cryptographic operations
    /// </summary>
    public static readonly NativeCULong CKF_DUAL_CRYPTO_OPERATIONS = new(0x00000200);

    /// <summary>
    /// True if the token has been initialized using C_InitializeToken or an equivalent mechanism outside the scope of this standard. Calling C_InitializeToken when this flag is set will cause the token to be reinitialized.
    /// </summary>
    public static readonly NativeCULong CKF_TOKEN_INITIALIZED = new(0x00000400);

    /// <summary>
    /// True if the token supports secondary authentication for private key objects.
    /// </summary>
    public static readonly NativeCULong CKF_SECONDARY_AUTHENTICATION = new(0x00000800);

    /// <summary>
    /// True if an incorrect user login PIN has been entered at least once since the last successful authentication.
    /// </summary>
    public static readonly NativeCULong CKF_USER_PIN_COUNT_LOW = new(0x00010000);

    /// <summary>
    /// True if supplying an incorrect user PIN will it to become locked.
    /// </summary>
    public static readonly NativeCULong CKF_USER_PIN_FINAL_TRY = new(0x00020000);

    /// <summary>
    /// True if the user PIN has been locked. User login to the token is not possible.
    /// </summary>
    public static readonly NativeCULong CKF_USER_PIN_LOCKED = new(0x00040000);

    /// <summary>
    /// True if the user PIN value is the default value set by token initialization or manufacturing, or the PIN has been expired by the card.
    /// </summary>
    public static readonly NativeCULong CKF_USER_PIN_TO_BE_CHANGED = new(0x00080000);

    /// <summary>
    /// True if an incorrect SO login PIN has been entered at least once since the last successful authentication.
    /// </summary>
    public static readonly NativeCULong CKF_SO_PIN_COUNT_LOW = new(0x00100000);

    /// <summary>
    /// True if supplying an incorrect SO PIN will it to become locked.
    /// </summary>
    public static readonly NativeCULong CKF_SO_PIN_FINAL_TRY = new(0x00200000);

    /// <summary>
    /// True if the SO PIN has been locked. User login to the token is not possible.
    /// </summary>
    public static readonly NativeCULong CKF_SO_PIN_LOCKED = new(0x00400000);

    /// <summary>
    /// True if the SO PIN value is the default value set by token initialization or manufacturing, or the PIN has been expired by the card.
    /// </summary>
    public static readonly NativeCULong CKF_SO_PIN_TO_BE_CHANGED = new(0x00800000);

    /// <summary>
    /// True if the token failed a FIPS 140-2 self-test and entered an error state.
    /// </summary>
    public static readonly NativeCULong CKF_ERROR_STATE = new(0x01000000);

    /// <summary>
    /// True if the session is read/write; false if the session is read-only
    /// </summary>
    public static readonly NativeCULong CKF_RW_SESSION = new(0x00000002);

    /// <summary>
    /// This flag is provided for backward compatibility, and should always be set to true
    /// </summary>
    public static readonly NativeCULong CKF_SERIAL_SESSION = new(0x00000004);

    /// <summary>
    /// Identifies attribute whose value is an array of attributes
    /// </summary>
    public static readonly NativeCULong CKF_ARRAY_ATTRIBUTE = new(0x40000000);

    /// <summary>
    /// True if the mechanism is performed by the device; false if the mechanism is performed in software
    /// </summary>
    public static readonly NativeCULong CKF_HW = new(0x00000001);

    /// <summary>
    /// True if the mechanism can be used with C_EncryptInit
    /// </summary>
    public static readonly NativeCULong CKF_ENCRYPT = new(0x00000100);

    /// <summary>
    /// True if the mechanism can be used with C_DecryptInit
    /// </summary>
    public static readonly NativeCULong CKF_DECRYPT = new(0x00000200);

    /// <summary>
    /// True if the mechanism can be used with C_DigestInit
    /// </summary>
    public static readonly NativeCULong CKF_DIGEST = new(0x00000400);

    /// <summary>
    /// True if the mechanism can be used with C_SignInit
    /// </summary>
    public static readonly NativeCULong CKF_SIGN = new(0x00000800);

    /// <summary>
    /// True if the mechanism can be used with C_SignRecoverInit
    /// </summary>
    public static readonly NativeCULong CKF_SIGN_RECOVER = new(0x00001000);

    /// <summary>
    /// True if the mechanism can be used with C_VerifyInit
    /// </summary>
    public static readonly NativeCULong CKF_VERIFY = new(0x00002000);

    /// <summary>
    /// True if the mechanism can be used with C_VerifyRecoverInit
    /// </summary>
    public static readonly NativeCULong CKF_VERIFY_RECOVER = new(0x00004000);

    /// <summary>
    /// True if the mechanism can be used with C_GenerateKey
    /// </summary>
    public static readonly NativeCULong CKF_GENERATE = new(0x00008000);

    /// <summary>
    /// True if the mechanism can be used with C_GenerateKeyPair
    /// </summary>
    public static readonly NativeCULong CKF_GENERATE_KEY_PAIR = new(0x00010000);

    /// <summary>
    /// True if the mechanism can be used with C_WrapKey
    /// </summary>
    public static readonly NativeCULong CKF_WRAP = new(0x00020000);

    /// <summary>
    /// True if the mechanism can be used with C_UnwrapKey
    /// </summary>
    public static readonly NativeCULong CKF_UNWRAP = new(0x00040000);

    /// <summary>
    /// True if the mechanism can be used with C_DeriveKey
    /// </summary>
    public static readonly NativeCULong CKF_DERIVE = new(0x00080000);

    /// <summary>
    /// True if the mechanism can be used with EC domain parameters over Fp
    /// </summary>
    public static readonly NativeCULong CKF_EC_F_P = new(0x00100000);

    /// <summary>
    /// True if the mechanism can be used with EC domain parameters over F2m
    /// </summary>
    public static readonly NativeCULong CKF_EC_F_2M = new(0x00200000);

    /// <summary>
    /// True if the mechanism can be used with EC domain parameters of the choice ecParameters
    /// </summary>
    public static readonly NativeCULong CKF_EC_ECPARAMETERS = new(0x00400000);

    /// <summary>
    /// True if the mechanism can be used with EC domain parameters of the choice namedCurve
    /// </summary>
    public static readonly NativeCULong CKF_EC_NAMEDCURVE = new(0x00800000);

    /// <summary>
    /// True if the mechanism can be used with elliptic curve point uncompressed
    /// </summary>
    public static readonly NativeCULong CKF_EC_UNCOMPRESS = new(0x01000000);

    /// <summary>
    /// True if the mechanism can be used with elliptic curve point compressed
    /// </summary>
    public static readonly NativeCULong CKF_EC_COMPRESS = new(0x02000000);

    /// <summary>
    /// True if there is an extension to the flags; false if no extensions
    /// </summary>
    public static readonly NativeCULong CKF_EXTENSION = new(0x80000000);

    /// <summary>
    /// True if application threads which are executing calls to the library may not use native operating system calls to spawn new threads; false if they may
    /// </summary>
    public static readonly NativeCULong CKF_LIBRARY_CANT_CREATE_OS_THREADS = new(0x00000001);

    /// <summary>
    /// True if the library can use the native operation system threading model for locking; false otherwise
    /// </summary>
    public static readonly NativeCULong CKF_OS_LOCKING_OK = new(0x00000002);

    /// <summary>
    /// Flag indicating that C_WaitForSlotEvent should not block until an event occurs - it should return immediately instead
    /// </summary>
    public static readonly NativeCULong CKF_DONT_BLOCK = new(1);

    /// <summary>
    /// True if the OTP computation shall be for the next OTP, rather than the current one
    /// </summary>
    public static readonly NativeCULong CKF_NEXT_OTP = new(0x00000001);

    /// <summary>
    /// True if the OTP computation must not include a time value
    /// </summary>
    public static readonly NativeCULong CKF_EXCLUDE_TIME = new(0x00000002);

    /// <summary>
    /// True if the OTP computation must not include a counter value
    /// </summary>
    public static readonly NativeCULong CKF_EXCLUDE_COUNTER = new(0x00000004);

    /// <summary>
    /// True if the OTP computation must not include a challenge
    /// </summary>
    public static readonly NativeCULong CKF_EXCLUDE_CHALLENGE = new(0x00000008);

    /// <summary>
    /// True if the OTP computation must not include a PIN value
    /// </summary>
    public static readonly NativeCULong CKF_EXCLUDE_PIN = new(0x00000010);

    /// <summary>
    /// True if the OTP returned shall be in a form suitable for human consumption
    /// </summary>
    public static readonly NativeCULong CKF_USER_FRIENDLY_OTP = new(0x00000020);

    // === PKCS#11 v3.2 ===================================================

    /// <summary>
    /// Session flag: this session was opened with async-API semantics (PKCS#11 v3.2).
    /// Crypto operations on the session may return <see cref="CKR.CKR_PENDING"/>;
    /// caller retrieves results via C_AsyncComplete.
    /// </summary>
    public static readonly NativeCULong CKF_ASYNC_SESSION = new(0x00000008);

    /// <summary>
    /// Token-info flag: the token supports the async API (PKCS#11 v3.2).
    /// </summary>
    public static readonly NativeCULong CKF_ASYNC_SESSION_SUPPORTED = new(0x04000000);

    /// <summary>
    /// Mechanism-info flag: mechanism can be used with C_EncapsulateKey (PKCS#11 v3.2).
    /// </summary>
    public static readonly NativeCULong CKF_ENCAPSULATE = new(0x10000000);

    /// <summary>
    /// Mechanism-info flag: mechanism can be used with C_DecapsulateKey (PKCS#11 v3.2).
    /// </summary>
    public static readonly NativeCULong CKF_DECAPSULATE = new(0x20000000);
}