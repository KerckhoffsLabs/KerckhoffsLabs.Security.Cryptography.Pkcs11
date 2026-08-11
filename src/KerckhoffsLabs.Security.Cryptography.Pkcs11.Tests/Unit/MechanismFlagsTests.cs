using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

public sealed class MechanismFlagsTests : FlagsContract<MechanismFlags>
{
    protected override MechanismFlags Make(ulong bits) => new(bits);
    protected override ulong RawValueOf(MechanismFlags flags) => flags.Flags;

    protected override (string Name, ulong Bit, Func<MechanismFlags, bool> Get)[] All =>
    [
        (nameof(MechanismFlags.Hw), CKF.CKF_HW, f => f.Hw),
        (nameof(MechanismFlags.Encrypt), CKF.CKF_ENCRYPT, f => f.Encrypt),
        (nameof(MechanismFlags.Decrypt), CKF.CKF_DECRYPT, f => f.Decrypt),
        (nameof(MechanismFlags.Digest), CKF.CKF_DIGEST, f => f.Digest),
        (nameof(MechanismFlags.Sign), CKF.CKF_SIGN, f => f.Sign),
        (nameof(MechanismFlags.SignRecover), CKF.CKF_SIGN_RECOVER, f => f.SignRecover),
        (nameof(MechanismFlags.Verify), CKF.CKF_VERIFY, f => f.Verify),
        (nameof(MechanismFlags.VerifyRecover), CKF.CKF_VERIFY_RECOVER, f => f.VerifyRecover),
        (nameof(MechanismFlags.Generate), CKF.CKF_GENERATE, f => f.Generate),
        (nameof(MechanismFlags.GenerateKeyPair), CKF.CKF_GENERATE_KEY_PAIR, f => f.GenerateKeyPair),
        (nameof(MechanismFlags.Wrap), CKF.CKF_WRAP, f => f.Wrap),
        (nameof(MechanismFlags.Unwrap), CKF.CKF_UNWRAP, f => f.Unwrap),
        (nameof(MechanismFlags.Derive), CKF.CKF_DERIVE, f => f.Derive),
        (nameof(MechanismFlags.Extension), CKF.CKF_EXTENSION, f => f.Extension),
        (nameof(MechanismFlags.EcFp), CKF.CKF_EC_F_P, f => f.EcFp),
        (nameof(MechanismFlags.EcF2m), CKF.CKF_EC_F_2M, f => f.EcF2m),
        (nameof(MechanismFlags.EcEcParameters), CKF.CKF_EC_ECPARAMETERS, f => f.EcEcParameters),
        (nameof(MechanismFlags.EcNamedCurve), CKF.CKF_EC_NAMEDCURVE, f => f.EcNamedCurve),
        (nameof(MechanismFlags.EcUncompress), CKF.CKF_EC_UNCOMPRESS, f => f.EcUncompress),
        (nameof(MechanismFlags.EcCompress), CKF.CKF_EC_COMPRESS, f => f.EcCompress),
    ];
}
