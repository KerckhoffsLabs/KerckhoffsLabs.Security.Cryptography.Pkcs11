using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Backend-agnostic assertions for <c>Pkcs11Session.GenerateEcKeyPair</c>. The per-backend test
/// classes live in <c>GenerateEcKeyPairTests.Pkcs11Mock.cs</c> and <c>GenerateEcKeyPairTests.SoftHsm2.cs</c>.
/// (The sub-128-bit-curve insecure gate is covered separately in <c>GenerateEcKeyPairInsecureGateTests</c>.)
/// <c>EcKeyGen_CurveOidNotACurve_IsRefused</c> goes through the raw dispatch, with <c>CKA_EC_PARAMS</c> the library
/// would not send.
/// </summary>
internal static class GenerateEcKeyPairTestCases
{
    private static Pkcs11Session OpenSession(IPkcs11Backend backend) =>
        backend.OpenSession();

    internal static void Assert_GeneratesP256KeyPair(IPkcs11Backend backend)
    {
        using var session = OpenSession(backend);
        using var key = session.GenerateEcKeyPair(curve: Pkcs11ECCurve.NamedCurves.NistP256);

        Assert.False(key.PrivateHandle.IsInvalid);
        Assert.False(key.PublicHandle.IsInvalid);
    }

    internal static void Assert_RejectsUnspecifiedCurve(IPkcs11Backend backend)
    {
        using var session = OpenSession(backend);
        // The uninitialized default(Pkcs11ECCurve) carries no OID and must be rejected.
        Assert.Throws<ArgumentException>(() => session.GenerateEcKeyPair(curve: default(Pkcs11ECCurve)));
    }

    public static TheoryData<string> CurveOidsNotACurve => ["P-256 with an extra arc", "P-256 without its last arc"];

    // CKA_EC_PARAMS names the curve by its OID (PKCS#11 v3.2 §6.3.3). The P-256 OID with an arc added
    // (1.2.840.10045.3.1.7.1) or its last arc dropped (1.2.840.10045.3.1) names no curve, so
    // C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN) refuses it with CKR_CURVE_NOT_SUPPORTED or CKR_DOMAIN_PARAMS_INVALID
    // (§5.1.6), or CKR_ATTRIBUTE_VALUE_INVALID for the attribute (§4.1), and makes no key: a module that compares
    // only the bytes the OIDs share would make a P-256 key.
    internal static void Assert_EcKeyGen_CurveOidNotACurve_IsRefused(IPkcs11Backend backend, string oid)
    {
        backend.RequireMechanism(CKM.CKM_EC_KEY_PAIR_GEN);
        byte[] ecParams = oid == "P-256 with an extra arc"
            ? [0x06, 0x09, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x01]
            : [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01];
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            using var pubClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
            using var privClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            using var keyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
            using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var verify = new ObjectAttribute(CKA.CKA_VERIFY, true);
            using var sign = new ObjectAttribute(CKA.CKA_SIGN, true);
            using var parameters = new ObjectAttribute(CKA.CKA_EC_PARAMS, ecParams);
            using var scope = new MechanismParameterScope();
            CK_MECHANISM mech = new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN).Marshal(scope, out _);
            CK_ATTRIBUTE[] pubTemplate = [.. new[] { pubClass, keyType, token, verify, parameters }.Select(a => a.CkAttribute)];
            CK_ATTRIBUTE[] privTemplate = [.. new[] { privClass, keyType, token, sign }.Select(a => a.CkAttribute)];
            CKR rv = backend.Library.LowLevelLibrary!.C_GenerateKeyPair((NativeCULong)session.SessionId, in mech, pubTemplate, privTemplate,
                out NativeCULong pub, out NativeCULong priv);
            if (rv == CKR.CKR_OK)
            {
                session.DestroyObject(new ObjectHandle((ulong)priv));
                session.DestroyObject(new ObjectHandle((ulong)pub));
            }
            Assert.True(rv is CKR.CKR_CURVE_NOT_SUPPORTED or CKR.CKR_DOMAIN_PARAMS_INVALID or CKR.CKR_ATTRIBUTE_VALUE_INVALID,
                $"C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN) with CKA_EC_PARAMS of {oid} returned {rv}.");
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }
}
