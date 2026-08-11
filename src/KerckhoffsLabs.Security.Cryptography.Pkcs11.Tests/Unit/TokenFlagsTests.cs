using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

public sealed class TokenFlagsTests : FlagsContract<TokenFlags>
{
    protected override TokenFlags Make(ulong bits) => new(bits);
    protected override ulong RawValueOf(TokenFlags flags) => flags.Flags;

    protected override (string Name, ulong Bit, Func<TokenFlags, bool> Get)[] All =>
    [
        (nameof(TokenFlags.Rng), CKF.CKF_RNG, f => f.Rng),
        (nameof(TokenFlags.WriteProtected), CKF.CKF_WRITE_PROTECTED, f => f.WriteProtected),
        (nameof(TokenFlags.LoginRequired), CKF.CKF_LOGIN_REQUIRED, f => f.LoginRequired),
        (nameof(TokenFlags.UserPinInitialized), CKF.CKF_USER_PIN_INITIALIZED, f => f.UserPinInitialized),
        (nameof(TokenFlags.RestoreKeyNotNeeded), CKF.CKF_RESTORE_KEY_NOT_NEEDED, f => f.RestoreKeyNotNeeded),
        (nameof(TokenFlags.ClockOnToken), CKF.CKF_CLOCK_ON_TOKEN, f => f.ClockOnToken),
        (nameof(TokenFlags.ProtectedAuthenticationPath), CKF.CKF_PROTECTED_AUTHENTICATION_PATH, f => f.ProtectedAuthenticationPath),
        (nameof(TokenFlags.DualCryptoOperations), CKF.CKF_DUAL_CRYPTO_OPERATIONS, f => f.DualCryptoOperations),
        (nameof(TokenFlags.TokenInitialized), CKF.CKF_TOKEN_INITIALIZED, f => f.TokenInitialized),
        (nameof(TokenFlags.SecondaryAuthentication), CKF.CKF_SECONDARY_AUTHENTICATION, f => f.SecondaryAuthentication),
        (nameof(TokenFlags.UserPinCountLow), CKF.CKF_USER_PIN_COUNT_LOW, f => f.UserPinCountLow),
        (nameof(TokenFlags.UserPinFinalTry), CKF.CKF_USER_PIN_FINAL_TRY, f => f.UserPinFinalTry),
        (nameof(TokenFlags.UserPinLocked), CKF.CKF_USER_PIN_LOCKED, f => f.UserPinLocked),
        (nameof(TokenFlags.UserPinToBeChanged), CKF.CKF_USER_PIN_TO_BE_CHANGED, f => f.UserPinToBeChanged),
        (nameof(TokenFlags.SoPinCountLow), CKF.CKF_SO_PIN_COUNT_LOW, f => f.SoPinCountLow),
        (nameof(TokenFlags.SoPinFinalTry), CKF.CKF_SO_PIN_FINAL_TRY, f => f.SoPinFinalTry),
        (nameof(TokenFlags.SoPinLocked), CKF.CKF_SO_PIN_LOCKED, f => f.SoPinLocked),
        (nameof(TokenFlags.SoPinToBeChanged), CKF.CKF_SO_PIN_TO_BE_CHANGED, f => f.SoPinToBeChanged),
    ];
}
