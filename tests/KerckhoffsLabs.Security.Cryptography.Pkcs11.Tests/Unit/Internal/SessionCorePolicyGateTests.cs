using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

#pragma warning disable KLPKCS11009 // a refused mechanism is the subject under test

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// The session's policy gate on the entry points the backend gate tests don't reach: verify-recover,
/// stream verify, the dual-function decrypt-and-verify, and the PKCS#11 v3.2 authenticated wrap,
/// authenticated unwrap and signature-first verify. A refused mechanism must stop each with
/// <see cref="CryptoPolicyViolationException"/> before the module sees the call.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class SessionCorePolicyGateTests
{
    // Refused for every operation under SecureOnly: unlisted, and documented as broken.
    private static readonly Mechanism Refused = new(CKM.CKM_DES_ECB);

    // Allowed for both halves of the dual-function calls, so only the other half can refuse.
    private static readonly Mechanism AllowedVerify = new(CKM.CKM_SHA256_HMAC);
    private static readonly Mechanism AllowedDecrypt = new(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], [], 128));

    private static readonly string[] InitFunctions =
    [
        "C_VerifyInit", "C_VerifyRecoverInit", "C_VerifySignatureInit", "C_DecryptInit",
        "C_WrapKeyAuthenticated", "C_UnwrapKeyAuthenticated",
    ];

    // Every function the gated paths would call first answers CKR_OK, so a call that got past the gate
    // would be counted (and would not fail with the policy exception).
    private sealed class GateModule : SessionTestModule
    {
        protected override CKR C_VerifyInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_VerifyRecoverInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_VerifySignatureInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key, ReadOnlySpan<byte> signature) => CKR.CKR_OK;
        protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;

        protected override CKR C_WrapKeyAuthenticated(NativeCULong session, CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key,
            ReadOnlySpan<byte> associatedData, NativeBuffer<byte> wrappedKey, ref NativeCULong wrappedKeyLen) => CKR.CKR_OK;

        protected override CKR C_UnwrapKeyAuthenticated(NativeCULong session, CK_MECHANISM mechanism, NativeCULong unwrappingKey,
            ReadOnlySpan<byte> wrappedKey, CK_ATTRIBUTE[] template, ReadOnlySpan<byte> associatedData, ref NativeCULong key) => CKR.CKR_OK;
    }

    private static readonly ObjectHandle Key = new(1);

    // Keyed by name so each theory row is serializable; each entry makes one gated call, with the input
    // and output streams the theory owns.
    private static readonly Dictionary<string, Action<Pkcs11SessionCore, Stream, Stream>> GatedCalls = new()
    {
        ["VerifyRecover"] = (s, _, _) => s.VerifyRecover(Refused, Key, [1], out _),
        ["Verify(stream)"] = (s, input, _) => s.Verify(Refused, Key, input, [1]),
        ["Verify(stream, bufferLength)"] = (s, input, _) => s.Verify(Refused, Key, input, [1], 16),
        ["DecryptVerify, refused verify"] = (s, _, _) => s.DecryptVerify(Refused, Key, AllowedDecrypt, Key, [1], [1], out _),
        ["DecryptVerify, refused decrypt"] = (s, _, _) => s.DecryptVerify(AllowedVerify, Key, Refused, Key, [1], [1], out _),
        ["DecryptVerify(stream), refused verify"] = (s, input, output) => s.DecryptVerify(Refused, Key, AllowedDecrypt, Key, input, output, [1]),
        ["DecryptVerify(stream), refused decrypt"] = (s, input, output) => s.DecryptVerify(AllowedVerify, Key, Refused, Key, input, output, [1]),
        ["DecryptVerify(stream, bufferLength), refused verify"] = (s, input, output) => s.DecryptVerify(Refused, Key, AllowedDecrypt, Key, input, output, [1], 16),
        ["DecryptVerify(stream, bufferLength), refused decrypt"] = (s, input, output) => s.DecryptVerify(AllowedVerify, Key, Refused, Key, input, output, [1], 16),
        ["WrapKeyAuthenticated"] = (s, _, _) => s.WrapKeyAuthenticated(Refused, Key, new ObjectHandle(2), [1]),
        ["UnwrapKeyAuthenticated"] = (s, _, _) => s.UnwrapKeyAuthenticated(Refused, Key, [1], [1], []),
        ["VerifySignature"] = (s, _, _) => s.VerifySignature(Refused, Key, [1], [1]),
        ["VerifySignature(stream)"] = (s, input, _) => s.VerifySignature(Refused, Key, [1], input),
    };

    public static TheoryData<string> GatedCallNames() => [.. GatedCalls.Keys];

    [Theory]
    [MemberData(nameof(GatedCallNames))]
    public void RefusedMechanism_IsStoppedBeforeTheModule(string call)
    {
        using var module = new GateModule();
        using Pkcs11SessionCore session = module.CreateSession(policy: CryptoPolicy.SecureOnly);

        using var input = new MemoryStream([1]);
        using var output = new MemoryStream();

        var e = Assert.Throws<CryptoPolicyViolationException>(() => GatedCalls[call](session, input, output));

        Assert.Equal(CKM.CKM_DES_ECB, e.Mechanism);
        Assert.All(InitFunctions, f => Assert.Equal(0, module.CallCount(f)));
    }
}
