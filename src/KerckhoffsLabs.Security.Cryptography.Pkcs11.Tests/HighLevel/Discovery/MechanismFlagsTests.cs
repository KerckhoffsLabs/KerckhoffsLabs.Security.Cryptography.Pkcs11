using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Discovery;

public sealed class MechanismFlagsTests
{
    // Every MechanismFlags bit property, paired with the CKF flag it must read. Each CKF_* in the
    // mechanism-info set is a distinct bit, so this table also asserts no two properties alias.
    private static readonly (string Name, ulong Bit, Func<MechanismFlags, bool> Get)[] All =
    [
        (nameof(MechanismFlags.Hw), CKF.CKF_HW.Value, f => f.Hw),
        (nameof(MechanismFlags.Encrypt), CKF.CKF_ENCRYPT.Value, f => f.Encrypt),
        (nameof(MechanismFlags.Decrypt), CKF.CKF_DECRYPT.Value, f => f.Decrypt),
        (nameof(MechanismFlags.Digest), CKF.CKF_DIGEST.Value, f => f.Digest),
        (nameof(MechanismFlags.Sign), CKF.CKF_SIGN.Value, f => f.Sign),
        (nameof(MechanismFlags.SignRecover), CKF.CKF_SIGN_RECOVER.Value, f => f.SignRecover),
        (nameof(MechanismFlags.Verify), CKF.CKF_VERIFY.Value, f => f.Verify),
        (nameof(MechanismFlags.VerifyRecover), CKF.CKF_VERIFY_RECOVER.Value, f => f.VerifyRecover),
        (nameof(MechanismFlags.Generate), CKF.CKF_GENERATE.Value, f => f.Generate),
        (nameof(MechanismFlags.GenerateKeyPair), CKF.CKF_GENERATE_KEY_PAIR.Value, f => f.GenerateKeyPair),
        (nameof(MechanismFlags.Wrap), CKF.CKF_WRAP.Value, f => f.Wrap),
        (nameof(MechanismFlags.Unwrap), CKF.CKF_UNWRAP.Value, f => f.Unwrap),
        (nameof(MechanismFlags.Derive), CKF.CKF_DERIVE.Value, f => f.Derive),
        (nameof(MechanismFlags.Extension), CKF.CKF_EXTENSION.Value, f => f.Extension),
        (nameof(MechanismFlags.EcFp), CKF.CKF_EC_F_P.Value, f => f.EcFp),
        (nameof(MechanismFlags.EcF2m), CKF.CKF_EC_F_2M.Value, f => f.EcF2m),
        (nameof(MechanismFlags.EcEcParameters), CKF.CKF_EC_ECPARAMETERS.Value, f => f.EcEcParameters),
        (nameof(MechanismFlags.EcNamedCurve), CKF.CKF_EC_NAMEDCURVE.Value, f => f.EcNamedCurve),
        (nameof(MechanismFlags.EcUncompress), CKF.CKF_EC_UNCOMPRESS.Value, f => f.EcUncompress),
        (nameof(MechanismFlags.EcCompress), CKF.CKF_EC_COMPRESS.Value, f => f.EcCompress),
    ];

    [Fact]
    public void EachFlag_SetInIsolation_TogglesOnlyItsOwnProperty()
    {
        foreach (var (name, bit, _) in All)
        {
            var flags = new MechanismFlags((NativeCULong)bit);
            foreach (var (otherName, _, get) in All)
                Assert.Equal(otherName == name, get(flags));
        }
    }

    [Fact]
    public void NoBitsSet_AllPropertiesFalse()
    {
        var flags = new MechanismFlags((NativeCULong)0UL);
        Assert.Equal(0UL, flags.Flags);
        Assert.All(All, e => Assert.False(e.Get(flags)));
    }

    [Fact]
    public void AllBitsSet_AllPropertiesTrue()
    {
        ulong all = 0;
        foreach (var (_, bit, _) in All) all |= bit;
        var flags = new MechanismFlags((NativeCULong)all);
        Assert.All(All, e => Assert.True(e.Get(flags)));
    }

    [Fact]
    public void Flags_ExposesRawValue()
    {
        var flags = new MechanismFlags((NativeCULong)0x12340UL);
        Assert.Equal(0x12340UL, flags.Flags);
    }

    [Fact]
    public void Record_ValueEquality()
    {
        Assert.Equal(new MechanismFlags((NativeCULong)0x300UL), new MechanismFlags((NativeCULong)0x300UL));
        Assert.NotEqual(new MechanismFlags((NativeCULong)0x300UL), new MechanismFlags((NativeCULong)0x100UL));
    }
}
