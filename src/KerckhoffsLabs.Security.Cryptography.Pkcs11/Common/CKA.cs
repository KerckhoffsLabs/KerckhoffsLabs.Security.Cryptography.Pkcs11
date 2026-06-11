using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

/// <summary>
/// Attributes
/// </summary>
public enum CKA : uint
{
    /// <summary>
    /// Object class (type) [CKO/uint]
    /// </summary>
    CKA_CLASS = 0x00000000,

    /// <summary>
    /// True if object is a token object; false if object is a session object [bool]
    /// </summary>
    CKA_TOKEN = 0x00000001,

    /// <summary>
    /// True if object is a private object; false if object is a public object. [bool]
    /// </summary>
    CKA_PRIVATE = 0x00000002,

    /// <summary>
    /// Description of the object [string]
    /// </summary>
    CKA_LABEL = 0x00000003,

    /// <summary>
    /// Description of the application that manages the object [string]
    /// </summary>
    CKA_APPLICATION = 0x00000010,

    /// <summary>
    /// Value of the object [byte array]
    /// </summary>
    CKA_VALUE = 0x00000011,

    /// <summary>
    /// DER-encoding of the object identifier indicating the data object type [byte array]
    /// </summary>
    CKA_OBJECT_ID = 0x00000012,

    /// <summary>
    /// Type of certificate [CKC/uint]
    /// </summary>
    CKA_CERTIFICATE_TYPE = 0x00000080,

    /// <summary>
    /// DER-encoding of the certificate issuer name [byte array]
    /// </summary>
    CKA_ISSUER = 0x00000081,

    /// <summary>
    /// DER-encoding of the certificate serial number [byte array]
    /// </summary>
    CKA_SERIAL_NUMBER = 0x00000082,

    /// <summary>
    /// DER-encoding of the attribute certificate's issuer field. [byte array]
    /// </summary>
    CKA_AC_ISSUER = 0x00000083,

    /// <summary>
    /// DER-encoding of the attribute certificate's subject field. [byte array]
    /// </summary>
    CKA_OWNER = 0x00000084,

    /// <summary>
    /// BER-encoding of a sequence of object identifier values corresponding to the attribute types contained in the certificate. [byte array]
    /// </summary>
    CKA_ATTR_TYPES = 0x00000085,

    /// <summary>
    /// The certificate can be trusted for the application that it was created. [bool]
    /// </summary>
    CKA_TRUSTED = 0x00000086,

    /// <summary>
    /// Categorization of the certificate [uint]
    /// </summary>
    CKA_CERTIFICATE_CATEGORY = 0x00000087,

    /// <summary>
    /// Java MIDP security domain [uint]
    /// </summary>
    CKA_JAVA_MIDP_SECURITY_DOMAIN = 0x00000088,

    /// <summary>
    /// If not empty this attribute gives the URL where the complete certificate can be obtained [string]
    /// </summary>
    CKA_URL = 0x00000089,

    /// <summary>
    /// SHA-1 hash of the subject public key [byte array]
    /// </summary>
    CKA_HASH_OF_SUBJECT_PUBLIC_KEY = 0x0000008A,

    /// <summary>
    /// SHA-1 hash of the issuer public key [byte array]
    /// </summary>
    CKA_HASH_OF_ISSUER_PUBLIC_KEY = 0x0000008B,

    /// <summary>
    /// Defines the mechanism used to calculate CKA_HASH_OF_SUBJECT_PUBLIC_KEY and CKA_HASH_OF_ISSUER_PUBLIC_KEY. [CKM/uint]
    /// </summary>
    CKA_NAME_HASH_ALGORITHM = 0x0000008C,

    /// <summary>
    /// Checksum [byte array]
    /// </summary>
    CKA_CHECK_VALUE = 0x00000090,

    /// <summary>
    /// Type of key [CKK/uint]
    /// </summary>
    CKA_KEY_TYPE = 0x00000100,

    /// <summary>
    /// DER-encoding of the key subject name [byte array]
    /// </summary>
    CKA_SUBJECT = 0x00000101,

    /// <summary>
    /// Key identifier for public/private key pair [byte array]
    /// </summary>
    CKA_ID = 0x00000102,

    /// <summary>
    /// True if key is sensitive [bool]
    /// </summary>
    CKA_SENSITIVE = 0x00000103,

    /// <summary>
    /// True if key supports encryption [bool]
    /// </summary>
    CKA_ENCRYPT = 0x00000104,

    /// <summary>
    /// True if key supports decryption [bool]
    /// </summary>
    CKA_DECRYPT = 0x00000105,

    /// <summary>
    /// True if key supports wrapping (i.e., can be used to wrap other keys) [bool]
    /// </summary>
    CKA_WRAP = 0x00000106,

    /// <summary>
    /// True if key supports unwrapping (i.e., can be used to unwrap other keys) [bool]
    /// </summary>
    CKA_UNWRAP = 0x00000107,

    /// <summary>
    /// True if key supports signatures (i.e., authentication codes) where the signature is an appendix to the data [bool]
    /// </summary>
    CKA_SIGN = 0x00000108,

    /// <summary>
    /// True if key supports signatures where the data can be recovered from the signature [bool]
    /// </summary>
    CKA_SIGN_RECOVER = 0x00000109,

    /// <summary>
    /// True if key supports verification (i.e., of authentication codes) where the signature is an appendix to the data [bool]
    /// </summary>
    CKA_VERIFY = 0x0000010A,

    /// <summary>
    /// True if key supports verification where the data is recovered from the signature [bool]
    /// </summary>
    CKA_VERIFY_RECOVER = 0x0000010B,

    /// <summary>
    /// True if key supports key derivation (i.e., if other keys can be derived from this one) [bool]
    /// </summary>
    CKA_DERIVE = 0x0000010C,

    /// <summary>
    /// Start date for the certificate/key [DateTime]
    /// </summary>
    CKA_START_DATE = 0x00000110,

    /// <summary>
    /// End date for the certificate/key [DateTime]
    /// </summary>
    CKA_END_DATE = 0x00000111,

    /// <summary>
    /// Modulus n [byte array]
    /// </summary>
    CKA_MODULUS = 0x00000120,

    /// <summary>
    /// Length in bits of modulus n [uint]
    /// </summary>
    CKA_MODULUS_BITS = 0x00000121,

    /// <summary>
    /// Public exponent e [byte array]
    /// </summary>
    CKA_PUBLIC_EXPONENT = 0x00000122,

    /// <summary>
    /// Private exponent d [byte array]
    /// </summary>
    CKA_PRIVATE_EXPONENT = 0x00000123,

    /// <summary>
    /// Prime p [byte array]
    /// </summary>
    CKA_PRIME_1 = 0x00000124,

    /// <summary>
    /// Prime q [byte array]
    /// </summary>
    CKA_PRIME_2 = 0x00000125,

    /// <summary>
    /// Private exponent d modulo p-1 [byte array]
    /// </summary>
    CKA_EXPONENT_1 = 0x00000126,

    /// <summary>
    /// Private exponent d modulo q-1 [byte array]
    /// </summary>
    CKA_EXPONENT_2 = 0x00000127,

    /// <summary>
    /// CRT coefficient q^-1 mod p [byte array]
    /// </summary>
    CKA_COEFFICIENT = 0x00000128,

    /// <summary>
    /// DER-encoding of the SubjectPublicKeyInfo [byte array]
    /// </summary>
    CKA_PUBLIC_KEY_INFO = 0x00000129,

    /// <summary>
    /// Prime p (512 to 1024 bits, in steps of 64 bits) [byte array]
    /// </summary>
    CKA_PRIME = 0x00000130,

    /// <summary>
    /// Subprime q (160 bits) [byte array]
    /// </summary>
    CKA_SUBPRIME = 0x00000131,

    /// <summary>
    /// Base g [byte array]
    /// </summary>
    CKA_BASE = 0x00000132,

    /// <summary>
    /// Length of the prime value [uint]
    /// </summary>
    CKA_PRIME_BITS = 0x00000133,

    /// <summary>
    /// Length of the subprime value [uint]
    /// </summary>
    CKA_SUBPRIME_BITS = 0x00000134,

    /// <summary>Header alias for <see cref="CKA_SUBPRIME_BITS"/> (PKCS#11 v3.2 spelling).</summary>
    CKA_SUB_PRIME_BITS = CKA_SUBPRIME_BITS,

    /// <summary>
    /// Length in bits of private value x [uint]
    /// </summary>
    CKA_VALUE_BITS = 0x00000160,

    /// <summary>
    /// Length in bytes of key value [uint]
    /// </summary>
    CKA_VALUE_LEN = 0x00000161,

    /// <summary>
    /// True if key is extractable and can be wrapped [bool]
    /// </summary>
    CKA_EXTRACTABLE = 0x00000162,

    /// <summary>
    /// True only if key was either generated locally (i.e., on the token) or created as a copy of a key which had its CKA_LOCAL attribute set to true [bool]
    /// </summary>
    CKA_LOCAL = 0x00000163,

    /// <summary>
    /// True if key has never had the CKA_EXTRACTABLE attribute set to true [bool]
    /// </summary>
    CKA_NEVER_EXTRACTABLE = 0x00000164,

    /// <summary>
    /// True if key has always had the CKA_SENSITIVE attribute set to true [bool]
    /// </summary>
    CKA_ALWAYS_SENSITIVE = 0x00000165,

    /// <summary>
    /// Identifier of the mechanism used to generate the key material [CKM/uint]
    /// </summary>
    CKA_KEY_GEN_MECHANISM = 0x00000166,

    /// <summary>
    /// True if object can be modified [bool]
    /// </summary>
    CKA_MODIFIABLE = 0x00000170,

    /// <summary>
    /// True if object can be copied [bool]
    /// </summary>
    CKA_COPYABLE = 0x00000171,

    /// <summary>
    /// True if object can be destroyed [bool]
    /// </summary>
    CKA_DESTROYABLE = 0x00000172,

    /// <summary>
    /// DER-encoding of an ANSI X9.62 Parameters value [byte array]
    /// </summary>
    CKA_ECDSA_PARAMS = 0x00000180,

    /// <summary>
    /// DER-encoding of an ANSI X9.62 Parameters value [byte array]
    /// </summary>
    CKA_EC_PARAMS = 0x00000180,

    /// <summary>
    /// DER-encoding of ANSI X9.62 ECPoint value Q [byte array]
    /// </summary>
    CKA_EC_POINT = 0x00000181,

    /// <summary>
    /// True if the key requires a secondary authentication to take place before its use it allowed [bool]
    /// </summary>
    CKA_SECONDARY_AUTH = 0x00000200,

    /// <summary>
    /// Mask indicating the current state of the secondary authentication PIN [uint]
    /// </summary>
    CKA_AUTH_PIN_FLAGS = 0x00000201,

    /// <summary>
    /// If true, the user has to supply the PIN for each use (sign or decrypt) with the key [bool]
    /// </summary>
    CKA_ALWAYS_AUTHENTICATE = 0x00000202,

    /// <summary>
    /// True if the key can only be wrapped with a wrapping key that has CKA_TRUSTED set to true [bool]
    /// </summary>
    CKA_WRAP_WITH_TRUSTED = 0x00000210,

    /// <summary>
    /// The attribute template to match against any keys wrapped using this wrapping key. Keys that do not match cannot be wrapped. [List of ObjectAttribute / CK_ATTRIBUTE array]
    /// </summary>
    CKA_WRAP_TEMPLATE = 0x40000000 | 0x00000211,

    /// <summary>
    /// The attribute template to apply to any keys unwrapped using this wrapping key. Any user supplied template is applied after this template as if the object has already been created. [List of ObjectAttribute / CK_ATTRIBUTE array]
    /// </summary>
    CKA_UNWRAP_TEMPLATE = 0x40000000 | 0x00000212,

    /// <summary>
    /// The attribute template to apply to any keys derived using this key. Any user supplied template is applied after this template as if the object has already been created. [List of ObjectAttribute / CK_ATTRIBUTE array]
    /// </summary>
    CKA_DERIVE_TEMPLATE = 0x40000000 | 0x00000213,

    /// <summary>
    /// Format of OTP values produced with this key: CK_OTP_FORMAT_DECIMAL = Decimal, CK_OTP_FORMAT_HEXADECIMAL = Hexadecimal, CK_OTP_FORMAT_ALPHANUMERIC = Alphanumeric, CK_OTP_FORMAT_BINARY = Only binary values [uint]
    /// </summary>
    CKA_OTP_FORMAT = 0x00000220,

    /// <summary>
    /// Default length of OTP values (in the CKA_OTP_FORMAT) produced with this key [uint]
    /// </summary>
    CKA_OTP_LENGTH = 0x00000221,

    /// <summary>
    /// Interval between OTP values produced with this key, in seconds. [uint]
    /// </summary>
    CKA_OTP_TIME_INTERVAL = 0x00000222,

    /// <summary>
    /// Set to true when the token is capable of returning OTPs suitable for human consumption [bool]
    /// </summary>
    CKA_OTP_USER_FRIENDLY_MODE = 0x00000223,

    /// <summary>
    /// Parameter requirements when generating or verifying OTP values with this key: CK_OTP_PARAM_MANDATORY = A challenge must be supplied. CK_OTP_PARAM_OPTIONAL = A challenge may be supplied but need not be. CK_OTP_PARAM_IGNORED = A challenge, if supplied, will be ignored. [uint]
    /// </summary>
    CKA_OTP_CHALLENGE_REQUIREMENT = 0x00000224,

    /// <summary>
    /// Parameter requirements when generating or verifying OTP values with this key: CK_OTP_PARAM_MANDATORY = A time value must be supplied. CK_OTP_PARAM_OPTIONAL = A time value may be supplied but need not be. CK_OTP_PARAM_IGNORED = A time value, if supplied, will be ignored. [uint]
    /// </summary>
    CKA_OTP_TIME_REQUIREMENT = 0x00000225,

    /// <summary>
    /// Parameter requirements when generating or verifying OTP values with this key: CK_OTP_PARAM_MANDATORY = A counter value must be supplied. CK_OTP_PARAM_OPTIONAL = A counter value may be supplied but need not be. CK_OTP_PARAM_IGNORED = A counter value, if supplied, will be ignored. [uint]
    /// </summary>
    CKA_OTP_COUNTER_REQUIREMENT = 0x00000226,

    /// <summary>
    /// Parameter requirements when generating or verifying OTP values with this key: CK_OTP_PARAM_MANDATORY = A PIN value must be supplied. CK_OTP_PARAM_OPTIONAL = A PIN value may be supplied but need not be. CK_OTP_PARAM_IGNORED = A PIN value, if supplied, will be ignored. [uint]
    /// </summary>
    CKA_OTP_PIN_REQUIREMENT = 0x00000227,

    /// <summary>
    /// Value of the associated internal counter [byte array]
    /// </summary>
    CKA_OTP_COUNTER = 0x0000022E,

    /// <summary>
    /// Value of the associated internal UTC time in the form YYYYMMDDhhmmss [string]
    /// </summary>
    CKA_OTP_TIME = 0x0000022F,

    /// <summary>
    /// Text string that identifies a user associated with the OTP key (may be used to enhance the user experience). [string]
    /// </summary>
    CKA_OTP_USER_IDENTIFIER = 0x0000022A,

    /// <summary>
    /// Text string that identifies a service that may validate OTPs generated by this key [string]
    /// </summary>
    CKA_OTP_SERVICE_IDENTIFIER = 0x0000022B,

    /// <summary>
    /// Logotype image that identifies a service that may validate OTPs generated by this key. [byte array]
    /// </summary>
    CKA_OTP_SERVICE_LOGO = 0x0000022C,

    /// <summary>
    /// MIME type of the CKA_OTP_SERVICE_LOGO attribute value [string]
    /// </summary>
    CKA_OTP_SERVICE_LOGO_TYPE = 0x0000022D,

    /// <summary>
    /// DER-encoding of the object identifier indicating the data object type of GOST R 34.10-2001. [byte array]
    /// </summary>
    CKA_GOSTR3410_PARAMS = 0x00000250,

    /// <summary>
    /// DER-encoding of the object identifier indicating the data object type of GOST R 34.11-94. [byte array]
    /// </summary>
    CKA_GOSTR3411_PARAMS = 0x00000251,

    /// <summary>
    /// DER-encoding of the object identifier indicating the data object type of GOST 28147-89. [byte array]
    /// </summary>
    CKA_GOST28147_PARAMS = 0x00000252,

    /// <summary>
    /// Hardware feature (type) [CKH/uint]
    /// </summary>
    CKA_HW_FEATURE_TYPE = 0x00000300,

    /// <summary>
    /// The value of the counter will reset to a previously returned value if the token is initialized [bool]
    /// </summary>
    CKA_RESET_ON_INIT = 0x00000301,

    /// <summary>
    /// The value of the counter has been reset at least once at some point in time [bool]
    /// </summary>
    CKA_HAS_RESET = 0x00000302,

    /// <summary>
    /// Screen resolution (in pixels) in X-axis [uint]
    /// </summary>
    CKA_PIXEL_X = 0x00000400,

    /// <summary>
    /// Screen resolution (in pixels) in Y-axis [uint]
    /// </summary>
    CKA_PIXEL_Y = 0x00000401,

    /// <summary>
    /// DPI, pixels per inch [uint]
    /// </summary>
    CKA_RESOLUTION = 0x00000402,

    /// <summary>
    /// Number of character rows for character-oriented displays [uint]
    /// </summary>
    CKA_CHAR_ROWS = 0x00000403,

    /// <summary>
    /// Number of character columns for character-oriented displays [uint]
    /// </summary>
    CKA_CHAR_COLUMNS = 0x00000404,

    /// <summary>
    /// Color support [bool]
    /// </summary>
    CKA_COLOR = 0x00000405,

    /// <summary>
    /// The number of bits of color or grayscale information per pixel. [uint]
    /// </summary>
    CKA_BITS_PER_PIXEL = 0x00000406,

    /// <summary>
    /// String indicating supported character sets, as defined by IANA MIBenum sets (www.iana.org). Supported character sets are separated with ";" e.g. a token supporting iso-8859-1 and us-ascii would set the attribute value to "4;3". [string]
    /// </summary>
    CKA_CHAR_SETS = 0x00000480,

    /// <summary>
    /// String indicating supported content transfer encoding methods, as defined by IANA (www.iana.org). Supported methods are separated with ";" e.g. a token supporting 7bit, 8bit and base64 could set the attribute value to "7bit;8bit;base64". [string]
    /// </summary>
    CKA_ENCODING_METHODS = 0x00000481,

    /// <summary>
    /// String indicating supported (presentable) MIME-types, as defined by IANA (www.iana.org). Supported types are separated with ";" e.g. a token supporting MIME types "a/b", "a/c" and "a/d" would set the attribute value to "a/b;a/c;a/d". [string]
    /// </summary>
    CKA_MIME_TYPES = 0x00000482,

    /// <summary>
    /// The type of mechanism object [CKM/uint]
    /// </summary>
    CKA_MECHANISM_TYPE = 0x00000500,

    /// <summary>
    /// Attributes the token always will include in the set of CMS signed attributes [byte array]
    /// </summary>
    CKA_REQUIRED_CMS_ATTRIBUTES = 0x00000501,

    /// <summary>
    /// Attributes the token will include in the set of CMS signed attributes in the absence of any attributes specified by the application [byte array]
    /// </summary>
    CKA_DEFAULT_CMS_ATTRIBUTES = 0x00000502,

    /// <summary>
    /// Attributes the token may include in the set of CMS signed attributes upon request by the application [byte array]
    /// </summary>
    CKA_SUPPORTED_CMS_ATTRIBUTES = 0x00000503,

    /// <summary>
    /// A list of mechanisms allowed to be used with this key [List of CKM / List of uint / CKM array / uint array]
    /// </summary>
    CKA_ALLOWED_MECHANISMS = 0x40000000 | 0x00000600,

    /// <summary>
    /// Token-assigned unique identifier for the object, stable across sessions (PKCS#11 v3.0)
    /// </summary>
    CKA_UNIQUE_ID = 0x00000004,

    /// <summary>
    /// Profile ID for CKO_PROFILE objects (PKCS#11 v3.0)
    /// </summary>
    CKA_PROFILE_ID = 0x00000601,

    /// <summary>
    /// X2 Ratchet — bag (Signal protocol state, PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_BAG = 0x00000602,

    /// <summary>
    /// X2 Ratchet — bag size (PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_BAGSIZE = 0x00000603,

    /// <summary>
    /// X2 Ratchet — Bob’s first message flag (PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_BOBS1STMSG = 0x00000604,

    /// <summary>
    /// X2 Ratchet — receiving chain key (PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_CKR = 0x00000605,

    /// <summary>
    /// X2 Ratchet — sending chain key (PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_CKS = 0x00000606,

    /// <summary>
    /// X2 Ratchet — DH peer public (PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_DHP = 0x00000607,

    /// <summary>
    /// X2 Ratchet — DH receiving (PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_DHR = 0x00000608,

    /// <summary>
    /// X2 Ratchet — DH sending (PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_DHS = 0x00000609,

    /// <summary>
    /// X2 Ratchet — header key receiving (PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_HKR = 0x0000060A,

    /// <summary>
    /// X2 Ratchet — header key sending (PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_HKS = 0x0000060B,

    /// <summary>
    /// X2 Ratchet — role flag (PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_ISALICE = 0x0000060C,

    /// <summary>
    /// X2 Ratchet — next header key receiving (PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_NHKR = 0x0000060D,

    /// <summary>
    /// X2 Ratchet — next header key sending (PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_NHKS = 0x0000060E,

    /// <summary>
    /// X2 Ratchet — receiving counter (PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_NR = 0x0000060F,

    /// <summary>
    /// X2 Ratchet — sending counter (PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_NS = 0x00000610,

    /// <summary>
    /// X2 Ratchet — previous sending counter (PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_PNS = 0x00000611,

    /// <summary>
    /// X2 Ratchet — root key (PKCS#11 v3.0)
    /// </summary>
    CKA_X2RATCHET_RK = 0x00000612,

    /// <summary>
    /// HSS multi-tree levels per RFC 8554 (PKCS#11 v3.1)
    /// </summary>
    CKA_HSS_LEVELS = 0x00000617,

    /// <summary>
    /// HSS LMS algorithm type (PKCS#11 v3.1)
    /// </summary>
    CKA_HSS_LMS_TYPE = 0x00000618,

    /// <summary>
    /// HSS LM-OTS algorithm type (PKCS#11 v3.1)
    /// </summary>
    CKA_HSS_LMOTS_TYPE = 0x00000619,

    /// <summary>
    /// HSS per-level LMS algorithm types (array) (PKCS#11 v3.1)
    /// </summary>
    CKA_HSS_LMS_TYPES = 0x0000061A,

    /// <summary>
    /// HSS per-level LM-OTS algorithm types (array) (PKCS#11 v3.1)
    /// </summary>
    CKA_HSS_LMOTS_TYPES = 0x0000061B,

    /// <summary>
    /// HSS remaining one-time signing capacity (PKCS#11 v3.1)
    /// </summary>
    CKA_HSS_KEYS_REMAINING = 0x0000061C,

    /// <summary>
    /// PQC parameter-set identifier (e.g. ML-KEM-768, ML-DSA-65, SLH-DSA-SHAKE-128f) (PKCS#11 v3.2)
    /// </summary>
    CKA_PARAMETER_SET = 0x0000061D,

    /// <summary>
    /// Bit flags describing the validation state of an object (PKCS#11 v3.2)
    /// </summary>
    CKA_OBJECT_VALIDATION_FLAGS = 0x0000061E,

    /// <summary>
    /// Validation profile type (PKCS#11 v3.2)
    /// </summary>
    CKA_VALIDATION_TYPE = 0x0000061F,

    /// <summary>
    /// Validation profile version (PKCS#11 v3.2)
    /// </summary>
    CKA_VALIDATION_VERSION = 0x00000620,

    /// <summary>
    /// Validation level (e.g. FIPS 140-3 Level 2/3) (PKCS#11 v3.2)
    /// </summary>
    CKA_VALIDATION_LEVEL = 0x00000621,

    /// <summary>
    /// Validation module identifier (PKCS#11 v3.2)
    /// </summary>
    CKA_VALIDATION_MODULE_ID = 0x00000622,

    /// <summary>
    /// Per-validation-record flag (PKCS#11 v3.2)
    /// </summary>
    CKA_VALIDATION_FLAG = 0x00000623,

    /// <summary>
    /// Validation-authority type (PKCS#11 v3.2)
    /// </summary>
    CKA_VALIDATION_AUTHORITY_TYPE = 0x00000624,

    /// <summary>
    /// Validation country code (PKCS#11 v3.2)
    /// </summary>
    CKA_VALIDATION_COUNTRY = 0x00000625,

    /// <summary>
    /// Validation certificate identifier (PKCS#11 v3.2)
    /// </summary>
    CKA_VALIDATION_CERTIFICATE_IDENTIFIER = 0x00000626,

    /// <summary>
    /// Validation certificate URI (PKCS#11 v3.2)
    /// </summary>
    CKA_VALIDATION_CERTIFICATE_URI = 0x00000627,

    /// <summary>
    /// Validation-vendor URI (PKCS#11 v3.2)
    /// </summary>
    CKA_VALIDATION_VENDOR_URI = 0x00000628,

    /// <summary>
    /// Validation profile name (PKCS#11 v3.2)
    /// </summary>
    CKA_VALIDATION_PROFILE = 0x00000629,

    /// <summary>
    /// Template applied to encapsulated keys (PKCS#11 v3.2)
    /// </summary>
    CKA_ENCAPSULATE_TEMPLATE = 0x0000062A,

    /// <summary>
    /// Template applied to decapsulated keys (PKCS#11 v3.2)
    /// </summary>
    CKA_DECAPSULATE_TEMPLATE = 0x0000062B,

    /// <summary>
    /// Trust attribute: TLS server authentication (PKCS#11 v3.2)
    /// </summary>
    CKA_TRUST_SERVER_AUTH = 0x0000062C,

    /// <summary>
    /// Trust attribute: TLS client authentication (PKCS#11 v3.2)
    /// </summary>
    CKA_TRUST_CLIENT_AUTH = 0x0000062D,

    /// <summary>
    /// Trust attribute: code signing (PKCS#11 v3.2)
    /// </summary>
    CKA_TRUST_CODE_SIGNING = 0x0000062E,

    /// <summary>
    /// Trust attribute: S/MIME email protection (PKCS#11 v3.2)
    /// </summary>
    CKA_TRUST_EMAIL_PROTECTION = 0x0000062F,

    /// <summary>
    /// Trust attribute: IPsec / IKE (PKCS#11 v3.2)
    /// </summary>
    CKA_TRUST_IPSEC_IKE = 0x00000630,

    /// <summary>
    /// Trust attribute: time stamping (PKCS#11 v3.2)
    /// </summary>
    CKA_TRUST_TIME_STAMPING = 0x00000631,

    /// <summary>
    /// Trust attribute: OCSP responder signing (PKCS#11 v3.2)
    /// </summary>
    CKA_TRUST_OCSP_SIGNING = 0x00000632,

    /// <summary>
    /// True if the key supports encapsulation (e.g. ML-KEM public key) (PKCS#11 v3.2)
    /// </summary>
    CKA_ENCAPSULATE = 0x00000633,

    /// <summary>
    /// True if the key supports decapsulation (e.g. ML-KEM private key) (PKCS#11 v3.2)
    /// </summary>
    CKA_DECAPSULATE = 0x00000634,

    /// <summary>
    /// Pre-computed digest of the certificate body (PKCS#11 v3.2)
    /// </summary>
    CKA_HASH_OF_CERTIFICATE = 0x00000635,

    /// <summary>
    /// CRC-64 checksum of the public key for fast handle disambiguation (PKCS#11 v3.2)
    /// </summary>
    CKA_PUBLIC_CRC64_VALUE = 0x00000636,

    /// <summary>
    /// Deterministic seed used for hedged PQC signing or key generation (PKCS#11 v3.2)
    /// </summary>
    CKA_SEED = 0x00000637,

    /// <summary>
    /// Permanently reserved for token vendors
    /// </summary>
    CKA_VENDOR_DEFINED = 0x80000000
}

/// <summary>
/// Utility class that helps with data type conversions.
/// </summary>
public static class CKAExtensions
{
    /// <summary>
    /// Converts CKA to NativeCULong
    /// </summary>
    /// <param name="value">CKA that should be converted</param>
    /// <returns>NativeCULong with value from CKA</returns>
    public static NativeCULong ToCULong(this CKA value) => (NativeCULong)(ulong)value;

    /// <summary>
    /// Converts <see cref="NativeCULong"/> to <see cref="CKA"/>, validating that the value
    /// matches a defined enum member. Throws <see cref="InvalidEnumValueException"/> otherwise.
    /// </summary>
    public static CKA ToCKA(this NativeCULong value)
    {
        CKA result = (CKA)(ulong)value;
        if (!Enum.IsDefined(result))
            throw new InvalidEnumValueException(typeof(CKA), (ulong)value);
        return result;
    }
}
