using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>
/// Coverage for the PKCS#11 v3.2 dispatch surface (<c>C_EncapsulateKey</c>, <c>C_DecapsulateKey</c>,
/// <c>C_VerifySignatureInit/Verify/Update/Final</c>, <c>C_WrapKeyAuthenticated</c>,
/// <c>C_UnwrapKeyAuthenticated</c>, <c>C_GetSessionValidationFlags</c>, <c>C_AsyncComplete/GetID/Join</c>)
/// — previously 0% covered. Unlike the v3.0 message API, none of these symbols exist at all in
/// pkcs11-mock's function table (verified against vendor/pkcs11-mock/src/pkcs11-mock.c) — no
/// released backend in this project's test matrix implements v3.2 — so <c>Has*</c> is <c>false</c>
/// for every one of them and the guard clause in <c>LowLevelPkcs11Library</c> fires before any
/// native call is attempted. That guard clause, not real v3.2 behaviour, is what these tests pin:
/// a consumer must get a clean <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> response, never a
/// crash or an unhandled native call into a symbol that was never resolved.
/// </summary>
[Collection("Mock")]
public sealed class V32NotSupportedTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void IsV32ApiSupported_FalseForMock()
    {
        Assert.False(_backend.Library.LowLevelLibrary!.IsV32ApiSupported);
    }

    [Fact]
    public void EncapsulateKey_ReportsFunctionNotSupported()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var findPublic = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
            ObjectHandle publicKey = Assert.Single(session.FindAllObjects([findPublic]));

            var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
                session.EncapsulateKey(new Mechanism(CKM.CKM_ML_KEM), publicKey, [], expectedCiphertextLen: 32));
            Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.CloseSession();
        }
    }

    [Fact]
    public void DecapsulateKey_ReportsFunctionNotSupported()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var findPrivate = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            ObjectHandle privateKey = Assert.Single(session.FindAllObjects([findPrivate]));

            var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
                session.DecapsulateKey(new Mechanism(CKM.CKM_ML_KEM), privateKey, new byte[32], []));
            Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.CloseSession();
        }
    }

    [Fact]
    public void WrapKeyAuthenticated_ReportsFunctionNotSupported()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var findSecret = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            ObjectHandle secretKey = Assert.Single(session.FindAllObjects([findSecret]));

            var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
                session.WrapKeyAuthenticated(new Mechanism(CKM.CKM_AES_GCM), secretKey, secretKey, []));
            Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.CloseSession();
        }
    }

    [Fact]
    public void UnwrapKeyAuthenticated_ReportsFunctionNotSupported()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var findSecret = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            ObjectHandle secretKey = Assert.Single(session.FindAllObjects([findSecret]));

            var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
                session.UnwrapKeyAuthenticated(new Mechanism(CKM.CKM_AES_GCM), secretKey, new byte[16], [], []));
            Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.CloseSession();
        }
    }

    [Fact]
    public void VerifySignature_ReportsFunctionNotSupported()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var findPublic = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
            ObjectHandle publicKey = Assert.Single(session.FindAllObjects([findPublic]));

            var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
                session.VerifySignature(new Mechanism(CKM.CKM_SHA256_RSA_PKCS), publicKey, [1, 2, 3], "data"u8.ToArray()));
            Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.CloseSession();
        }
    }

    [Fact]
    public void GetSessionValidationFlags_ReportsFunctionNotSupported()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            var ex = Assert.ThrowsAny<Pkcs11Exception>(
                () => session.GetSessionValidationFlags(CksValidationFlagsType.CKS_LAST_VALIDATION_OK));
            Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.CloseSession();
        }
    }

    // Async* has no high-level Pkcs11Session wrapper at all, so it's driven through the internal
    // low-level accessor directly — the raw API returns CKR rather than throwing.
    [Fact]
    public void AsyncComplete_ReturnsFunctionNotSupported()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            ILowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
            var result = new CK_ASYNC_DATA();
            CKR rv = lowLevel.C_AsyncComplete((NativeCULong)session.SessionId, "C_GenerateRandom"u8, ref result);
            Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, rv);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.CloseSession();
        }
    }

    [Fact]
    public void AsyncGetID_ReturnsFunctionNotSupported()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            ILowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
            NativeCULong id = default;
            CKR rv = lowLevel.C_AsyncGetID((NativeCULong)session.SessionId, "C_GenerateRandom"u8, ref id);
            Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, rv);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.CloseSession();
        }
    }

    [Fact]
    public void AsyncJoin_ReturnsFunctionNotSupported()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            ILowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
            CKR rv = lowLevel.C_AsyncJoin((NativeCULong)session.SessionId, "C_GenerateRandom"u8, (NativeCULong)1, []);
            Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, rv);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.CloseSession();
        }
    }
}
