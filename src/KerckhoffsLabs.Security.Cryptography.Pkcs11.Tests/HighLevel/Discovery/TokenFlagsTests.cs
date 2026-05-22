using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Discovery;

public sealed class TokenFlagsTests
{
    // Every TokenFlags bit property, paired with the CKF flag it must read. Each CKF_* is a
    // distinct bit, so this table also asserts no two properties alias the same bit.
    private static readonly (string Name, ulong Bit, Func<TokenFlags, bool> Get)[] All =
    [
        (nameof(TokenFlags.Rng), CKF.CKF_RNG.Value, f => f.Rng),
        (nameof(TokenFlags.WriteProtected), CKF.CKF_WRITE_PROTECTED.Value, f => f.WriteProtected),
        (nameof(TokenFlags.LoginRequired), CKF.CKF_LOGIN_REQUIRED.Value, f => f.LoginRequired),
        (nameof(TokenFlags.UserPinInitialized), CKF.CKF_USER_PIN_INITIALIZED.Value, f => f.UserPinInitialized),
        (nameof(TokenFlags.RestoreKeyNotNeeded), CKF.CKF_RESTORE_KEY_NOT_NEEDED.Value, f => f.RestoreKeyNotNeeded),
        (nameof(TokenFlags.ClockOnToken), CKF.CKF_CLOCK_ON_TOKEN.Value, f => f.ClockOnToken),
        (nameof(TokenFlags.ProtectedAuthenticationPath), CKF.CKF_PROTECTED_AUTHENTICATION_PATH.Value, f => f.ProtectedAuthenticationPath),
        (nameof(TokenFlags.DualCryptoOperations), CKF.CKF_DUAL_CRYPTO_OPERATIONS.Value, f => f.DualCryptoOperations),
        (nameof(TokenFlags.TokenInitialized), CKF.CKF_TOKEN_INITIALIZED.Value, f => f.TokenInitialized),
        (nameof(TokenFlags.SecondaryAuthentication), CKF.CKF_SECONDARY_AUTHENTICATION.Value, f => f.SecondaryAuthentication),
        (nameof(TokenFlags.UserPinCountLow), CKF.CKF_USER_PIN_COUNT_LOW.Value, f => f.UserPinCountLow),
        (nameof(TokenFlags.UserPinFinalTry), CKF.CKF_USER_PIN_FINAL_TRY.Value, f => f.UserPinFinalTry),
        (nameof(TokenFlags.UserPinLocked), CKF.CKF_USER_PIN_LOCKED.Value, f => f.UserPinLocked),
        (nameof(TokenFlags.UserPinToBeChanged), CKF.CKF_USER_PIN_TO_BE_CHANGED.Value, f => f.UserPinToBeChanged),
        (nameof(TokenFlags.SoPinCountLow), CKF.CKF_SO_PIN_COUNT_LOW.Value, f => f.SoPinCountLow),
        (nameof(TokenFlags.SoPinFinalTry), CKF.CKF_SO_PIN_FINAL_TRY.Value, f => f.SoPinFinalTry),
        (nameof(TokenFlags.SoPinLocked), CKF.CKF_SO_PIN_LOCKED.Value, f => f.SoPinLocked),
        (nameof(TokenFlags.SoPinToBeChanged), CKF.CKF_SO_PIN_TO_BE_CHANGED.Value, f => f.SoPinToBeChanged),
    ];

    [Fact]
    public void EachFlag_SetInIsolation_TogglesOnlyItsOwnProperty()
    {
        foreach (var (name, bit, _) in All)
        {
            var flags = new TokenFlags((NativeCULong)bit);
            foreach (var (otherName, _, get) in All)
                Assert.Equal(otherName == name, get(flags));
        }
    }

    [Fact]
    public void NoBitsSet_AllPropertiesFalse()
    {
        var flags = new TokenFlags((NativeCULong)0UL);
        Assert.Equal(0UL, flags.Flags);
        Assert.All(All, e => Assert.False(e.Get(flags)));
    }

    [Fact]
    public void AllBitsSet_AllPropertiesTrue()
    {
        ulong all = 0;
        foreach (var (_, bit, _) in All) all |= bit;
        var flags = new TokenFlags((NativeCULong)all);
        Assert.All(All, e => Assert.True(e.Get(flags)));
    }

    [Fact]
    public void Flags_ExposesRawValue()
    {
        var flags = new TokenFlags((NativeCULong)0x1234UL);
        Assert.Equal(0x1234UL, flags.Flags);
    }

    [Fact]
    public void Record_ValueEquality()
    {
        Assert.Equal(new TokenFlags((NativeCULong)5UL), new TokenFlags((NativeCULong)5UL));
        Assert.NotEqual(new TokenFlags((NativeCULong)5UL), new TokenFlags((NativeCULong)6UL));
    }
}
