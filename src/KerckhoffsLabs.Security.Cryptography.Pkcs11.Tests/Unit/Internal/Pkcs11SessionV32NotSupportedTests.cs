using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Verifies the documented sub-v3.2 contract: on a v2.40/v3.0/v3.1 module, every
/// v3.2 method of <see cref="Pkcs11Session"/> must fail cleanly with a typed
/// <see cref="Pkcs11Exception"/> carrying <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> — never
/// a null-delegate NRE. <see cref="Pkcs11Session.SupportsV32Api"/> is informational, not a
/// precondition guard, so the calls fall through to the dispatch layer, which the module below
/// reaches with those function pointers never bound. (The same contract is exercised end to end
/// against a real module by the spec-version-gate suite in <c>Integration/Compat</c>.)
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionV32NotSupportedTests
{
    private const ulong SessionId = 12;

    /// <summary>
    /// A sub-v3.2 module: it implements none of the v3.2 functions, so the loader leaves their
    /// slots unbound and the real dispatch layer's null-function-pointer guard answers
    /// <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/>.
    /// </summary>
    private sealed class NotSupportedFake : SessionTestModule;

    private static void AssertNotSupported(Action call)
    {
        var ex = Assert.ThrowsAny<Pkcs11Exception>(call);
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
    }

    [Fact]
    public void SupportsV32Api_ReportsFalse()
    {
        using var fake = new NotSupportedFake();
        using var s = fake.CreateSession(SessionId);
        Assert.False(s.SupportsV32Api);
    }

    [Fact]
    public void EncapsulateKey_Throws_FunctionNotSupported()
    {
        using var fake = new NotSupportedFake();
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_ML_KEM);
        AssertNotSupported(() => s.EncapsulateKey(mech, new ObjectHandle(1), []));
    }

    [Fact]
    public void DecapsulateKey_Throws_FunctionNotSupported()
    {
        using var fake = new NotSupportedFake();
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_ML_KEM);
        AssertNotSupported(() => s.DecapsulateKey(mech, new ObjectHandle(1), [1, 2, 3], []));
    }

    [Fact]
    public void WrapKeyAuthenticated_Throws_FunctionNotSupported()
    {
        using var fake = new NotSupportedFake();
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_GCM);
        AssertNotSupported(() => s.WrapKeyAuthenticated(mech, new ObjectHandle(1), new ObjectHandle(2), [0xAA]));
    }

    [Fact]
    public void UnwrapKeyAuthenticated_Throws_FunctionNotSupported()
    {
        using var fake = new NotSupportedFake();
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_GCM);
        AssertNotSupported(() => s.UnwrapKeyAuthenticated(mech, new ObjectHandle(1), [1, 2, 3], [0xCC], []));
    }

    [Fact]
    public void VerifySignature_OneShot_Throws_FunctionNotSupported()
    {
        using var fake = new NotSupportedFake();
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_ML_DSA);
        AssertNotSupported(() => s.VerifySignature(mech, new ObjectHandle(1), [9, 9], [1, 2, 3]));
    }

    [Fact]
    public void VerifySignature_Streaming_Throws_FunctionNotSupported()
    {
        using var fake = new NotSupportedFake();
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_ML_DSA);
        using var input = new MemoryStream([1, 2, 3, 4]);
        AssertNotSupported(() => s.VerifySignature(mech, new ObjectHandle(1), [9, 9], input, bufferLength: 2));
    }

    [Fact]
    public void GetSessionValidationFlags_Throws_FunctionNotSupported()
    {
        using var fake = new NotSupportedFake();
        using var s = fake.CreateSession(SessionId);
        AssertNotSupported(() => s.GetSessionValidationFlags(CksValidationFlagsType.CKS_LAST_VALIDATION_OK));
    }
}
