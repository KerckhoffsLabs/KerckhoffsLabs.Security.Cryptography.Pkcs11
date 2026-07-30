using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Verifies the documented sub-v3.2 contract: on a v2.40/v3.0/v3.1 module, every
/// v3.2 method of <see cref="Pkcs11Session"/> must fail cleanly with a typed
/// <see cref="Pkcs11Exception"/> carrying <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> — never
/// a null-delegate NRE. <see cref="Pkcs11Session.SupportsV32Api"/> is informational, not a
/// precondition guard, so the calls fall through to the dispatch layer; the fake below returns
/// exactly what the real <c>LowLevelPkcs11Library</c> returns when a function pointer was never
/// bound. (The same contract is exercised end to end against a real module by the
/// spec-version-gate suite in <c>Integration/Compat</c>.)
/// </summary>
public sealed class Pkcs11SessionV32NotSupportedTests
{
    private const ulong SessionId = 12;

    /// <summary>
    /// A sub-v3.2 module as the session sees it: the v3.2 surface reports unsupported and every
    /// v3.2 entry point returns <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/>, mirroring the real
    /// dispatch layer's null-function-pointer guard.
    /// </summary>
    private sealed class NotSupportedFake : FakeLowLevelPkcs11Library
    {
        public override bool IsV32ApiSupported => false;

        public override CKR C_EncapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong derivedKey)
            => CKR.CKR_FUNCTION_NOT_SUPPORTED;
        public override CKR C_DecapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, NativeCULong ciphertextLen, ref NativeCULong derivedKey)
            => CKR.CKR_FUNCTION_NOT_SUPPORTED;
        public override CKR C_WrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, byte[] associatedData, NativeCULong associatedDataLen, byte[]? wrappedKey, ref NativeCULong wrappedKeyLen)
            => CKR.CKR_FUNCTION_NOT_SUPPORTED;
        public override CKR C_UnwrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] associatedData, NativeCULong associatedDataLen, ref NativeCULong key)
            => CKR.CKR_FUNCTION_NOT_SUPPORTED;
        public override CKR C_VerifySignatureInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key, byte[] signature, NativeCULong signatureLen)
            => CKR.CKR_FUNCTION_NOT_SUPPORTED;
        public override CKR C_VerifySignature(NativeCULong session, byte[] data, NativeCULong dataLen)
            => CKR.CKR_FUNCTION_NOT_SUPPORTED;
        public override CKR C_VerifySignatureUpdate(NativeCULong session, byte[] part, NativeCULong partLen)
            => CKR.CKR_FUNCTION_NOT_SUPPORTED;
        public override CKR C_VerifySignatureFinal(NativeCULong session)
            => CKR.CKR_FUNCTION_NOT_SUPPORTED;
        public override CKR C_GetSessionValidationFlags(NativeCULong session, NativeCULong type, ref NativeCULong flags)
            => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    }

    private static Pkcs11Session NewSession() => new(new NotSupportedFake(), SessionId);

    private static void AssertNotSupported(Action call)
    {
        var ex = Assert.ThrowsAny<Pkcs11Exception>(call);
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
    }

    [Fact]
    public void SupportsV32Api_ReportsFalse()
        => Assert.False(NewSession().SupportsV32Api);

    [Fact]
    public void EncapsulateKey_Throws_FunctionNotSupported()
    {
        var s = NewSession();
        var mech = new Mechanism(CKM.CKM_ML_KEM);
        AssertNotSupported(() => s.EncapsulateKey(mech, new ObjectHandle(1), []));
    }

    [Fact]
    public void DecapsulateKey_Throws_FunctionNotSupported()
    {
        var s = NewSession();
        var mech = new Mechanism(CKM.CKM_ML_KEM);
        AssertNotSupported(() => s.DecapsulateKey(mech, new ObjectHandle(1), [1, 2, 3], []));
    }

    [Fact]
    public void WrapKeyAuthenticated_Throws_FunctionNotSupported()
    {
        var s = NewSession();
        var mech = new Mechanism(CKM.CKM_AES_GCM);
        AssertNotSupported(() => s.WrapKeyAuthenticated(mech, new ObjectHandle(1), new ObjectHandle(2), [0xAA]));
    }

    [Fact]
    public void UnwrapKeyAuthenticated_Throws_FunctionNotSupported()
    {
        var s = NewSession();
        var mech = new Mechanism(CKM.CKM_AES_GCM);
        AssertNotSupported(() => s.UnwrapKeyAuthenticated(mech, new ObjectHandle(1), [1, 2, 3], [0xCC], []));
    }

    [Fact]
    public void VerifySignature_OneShot_Throws_FunctionNotSupported()
    {
        var s = NewSession();
        var mech = new Mechanism(CKM.CKM_ML_DSA);
        AssertNotSupported(() => s.VerifySignature(mech, new ObjectHandle(1), [9, 9], [1, 2, 3]));
    }

    [Fact]
    public void VerifySignature_Streaming_Throws_FunctionNotSupported()
    {
        var s = NewSession();
        var mech = new Mechanism(CKM.CKM_ML_DSA);
        using var input = new MemoryStream([1, 2, 3, 4]);
        AssertNotSupported(() => s.VerifySignature(mech, new ObjectHandle(1), [9, 9], input, bufferLength: 2));
    }

    [Fact]
    public void GetSessionValidationFlags_Throws_FunctionNotSupported()
    {
        var s = NewSession();
        AssertNotSupported(() => s.GetSessionValidationFlags(CksValidationFlagsType.CKS_LAST_VALIDATION_OK));
    }
}
