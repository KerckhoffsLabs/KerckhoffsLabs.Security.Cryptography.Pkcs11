using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

public sealed class MechanismFlagsTests : FlagsContract<MechanismFlags>
{
    protected override MechanismFlags Make(ulong bits) => new((NativeCULong)bits);
    protected override ulong RawValueOf(MechanismFlags flags) => flags.Flags;

    protected override (string Name, ulong Bit, Func<MechanismFlags, bool> Get)[] All =>
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
}
