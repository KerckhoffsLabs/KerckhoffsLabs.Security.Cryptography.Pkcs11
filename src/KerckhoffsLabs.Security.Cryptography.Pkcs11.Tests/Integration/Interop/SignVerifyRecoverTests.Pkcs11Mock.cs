using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// pkcs11-mock's C_SignRecoverInit/C_VerifyRecoverInit only recognize CKM_RSA_PKCS (no OAEP
// variant), and these tests drive the raw low-level dispatch directly rather than through
// Pkcs11Session's runtime gate, so the compile-time warning is suppressed for this file only —
// the per-id suppression the diagnostic exists to enable.
#pragma warning disable KLPKCS11008

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Interop;

/// <summary>
/// Coverage for <c>C_SignRecoverInit</c>/<c>C_SignRecover</c> — previously 0% covered, since
/// <see cref="Pkcs11Session"/> has no high-level wrapper for the sign side (only
/// <see cref="Pkcs11Session.VerifyRecover"/> exists). Driven directly through the internal
/// low-level accessor instead. pkcs11-mock implements both for real: each does a deterministic
/// <c>output[i] = input[i] ^ 0xAB</c> transform (verified against
/// vendor/pkcs11-mock/src/pkcs11-mock.c), so <c>SignRecover</c> followed by <c>VerifyRecover</c>
/// round-trips back to the original data — XOR is its own inverse.
/// </summary>
[Collection("Mock")]
public sealed class SignVerifyRecoverTests(MockBackendFixture f)
{
    private readonly MockBackendFixture _backend = f;

    [Fact]
    public void SignRecover_ThenVerifyRecover_RoundTripsViaXorAb()
    {
        var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var findPrivate = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            ObjectHandle privateKey = Assert.Single(session.FindAllObjects([findPrivate]));

            ILowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
            var sessionId = (NativeCULong)session.SessionId;
            byte[] data = "sign-recover round trip"u8.ToArray();

            using (var scope = new MechanismParameterScope())
            {
                CK_MECHANISM ckMechanism = new Mechanism(CKM.CKM_RSA_PKCS).Marshal(scope, out _);
                CKR rv = lowLevel.C_SignRecoverInit(sessionId, ref ckMechanism, (NativeCULong)privateKey.ObjectId);
                Assert.Equal(CKR.CKR_OK, rv);
            }

            // Two-pass probe, per the standard PKCS#11 idiom: null buffer reports the length first.
            CKR probeRv = lowLevel.C_SignRecover(sessionId, data, null, out NativeCULong sigLen);
            Assert.Equal(CKR.CKR_OK, probeRv);
            Assert.Equal((NativeCULong)data.Length, sigLen);

            byte[] signature = new byte[(int)sigLen];
            CKR signRv = lowLevel.C_SignRecover(sessionId, data, signature, out sigLen);
            Assert.Equal(CKR.CKR_OK, signRv);

            byte[] expectedSignature = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                expectedSignature[i] = (byte)(data[i] ^ 0xAB);
            Assert.Equal(expectedSignature, signature);

            using var findPublic = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
            ObjectHandle publicKey = Assert.Single(session.FindAllObjects([findPublic]));

            using (var scope = new MechanismParameterScope())
            {
                CK_MECHANISM ckMechanism = new Mechanism(CKM.CKM_RSA_PKCS).Marshal(scope, out _);
                CKR rv = lowLevel.C_VerifyRecoverInit(sessionId, ref ckMechanism, (NativeCULong)publicKey.ObjectId);
                Assert.Equal(CKR.CKR_OK, rv);
            }

            byte[] recovered = new byte[signature.Length];
            CKR verifyRv = lowLevel.C_VerifyRecover(sessionId, signature, recovered, out NativeCULong recoveredLen);
            Assert.Equal(CKR.CKR_OK, verifyRv);
            Assert.Equal((NativeCULong)data.Length, recoveredLen);
            Assert.Equal(data, recovered);
        }
        finally
        {
            TestKeys.LogoutIfRequired(_backend, session);
            session.CloseSession();
        }
    }
}
