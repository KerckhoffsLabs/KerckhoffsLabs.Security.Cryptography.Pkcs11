using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>
/// Coverage for the PKCS#11 v3.0 message-based AEAD/sign/verify dispatch
/// (<c>LowLevelPkcs11Library.MessageEncryption/Decryption/Signing/Verifying.cs</c> and their
/// <c>Delegates.*</c> counterparts). pkcs11-mock advertises the full v3.0 function table — every
/// <c>C_Message*</c> symbol resolves, so <see cref="Pkcs11Session.SupportsMessageApi"/> reports
/// <c>true</c> — but each function's body is a hard-coded <c>return CKR_FUNCTION_NOT_SUPPORTED;</c>
/// stub (verified against vendor/pkcs11-mock/src/pkcs11-mock.c). That distinction — a module can
/// advertise a v3.0+ function in its table without the call actually working — is itself worth
/// pinning, and calling each function for real (rather than skipping because "Mock doesn't support
/// it") is exactly what exercises the previously-untested dispatch lines.
/// </summary>
[Collection("Mock")]
public sealed class MessageApiTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void SupportsMessageApi_TrueForMock_SymbolsResolveEvenThoughCallsAreStubbed()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            Assert.True(session.SupportsMessageApi);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.Dispose();
        }
    }

    [Fact]
    public void MessageEncrypt_ReportsFunctionNotSupported()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var findClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            ObjectHandle key = Assert.Single(session.FindAllObjects([findClass]));

            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure); // CKM_AES_GCM's IV size is not what's under test here
            var mechanism = new Mechanism(CKM.CKM_AES_GCM);
            var messageParams = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);

            var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
            {
                session.MessageEncrypt(mechanism, key, messageParams, [], "plaintext"u8.ToArray());
            });
            Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.Dispose();
        }
    }

    [Fact]
    public void MessageDecrypt_ReportsFunctionNotSupported()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var findClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            ObjectHandle key = Assert.Single(session.FindAllObjects([findClass]));

            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            var mechanism = new Mechanism(CKM.CKM_AES_GCM);
            var messageParams = CkmGcmMessageParams.ForDecrypt(new byte[12], new byte[16]);

            var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
            {
                session.MessageDecrypt(mechanism, key, messageParams, [], "ciphertext-ish"u8.ToArray());
            });
            Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.Dispose();
        }
    }

    // Message-based sign/verify have no high-level Pkcs11Session wrapper (unlike MessageEncrypt/
    // MessageDecrypt), so these go through the internal low-level accessor directly — the raw API
    // returns CKR rather than throwing, which is exactly the boundary LowLevelPkcs11Library owns.
    [Fact]
    public void MessageSignInit_ReturnsFunctionNotSupported()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var findClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            ObjectHandle key = Assert.Single(session.FindAllObjects([findClass]));

            ILowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
            using var scope = new MechanismParameterScope();
            CK_MECHANISM ckMechanism = new Mechanism(CKM.CKM_SHA256_RSA_PKCS).Marshal(scope, out _);

            CKR rv = lowLevel.C_MessageSignInit((NativeCULong)session.SessionId, ref ckMechanism, (NativeCULong)key.ObjectId);
            Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, rv);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.Dispose();
        }
    }

    [Fact]
    public void MessageVerifyInit_ReturnsFunctionNotSupported()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var findClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
            ObjectHandle key = Assert.Single(session.FindAllObjects([findClass]));

            ILowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
            using var scope = new MechanismParameterScope();
            CK_MECHANISM ckMechanism = new Mechanism(CKM.CKM_SHA256_RSA_PKCS).Marshal(scope, out _);

            CKR rv = lowLevel.C_MessageVerifyInit((NativeCULong)session.SessionId, ref ckMechanism, (NativeCULong)key.ObjectId);
            Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, rv);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.Dispose();
        }
    }
}
