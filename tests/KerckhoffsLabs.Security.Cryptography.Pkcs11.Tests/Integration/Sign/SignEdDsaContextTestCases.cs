using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// Drives <see cref="CkmEddsaParams"/>'s two non-vanilla modes against a real token: Ed25519ctx
/// (context-bound, <c>phFlag: false</c> with non-empty context data) and Ed25519ph (prehash,
/// <c>phFlag: true</c>). Every other EdDSA test in this suite either omits the parameter entirely or
/// passes it with an empty context (plain Ed25519/Ed448); these cases exercise what
/// <c>CkmEddsaParams</c> exists for. For Ed25519ph the token hashes the raw message internally per
/// RFC 8032, so the caller supplies the message, not a pre-computed digest.
/// </summary>
internal static class SignEdDsaContextTestCases
{
    private static void RequireEdDsa(IPkcs11Backend backend)
    {
        if (!backend.Supports(CKM.CKM_EDDSA) || !backend.Supports(CKM.CKM_EC_EDWARDS_KEY_PAIR_GEN))
            Assert.Skip("Backend does not advertise CKM_EDDSA and CKM_EC_EDWARDS_KEY_PAIR_GEN.");
    }

    internal static void Assert_Ed25519ctx_WithContext_RoundTrips(IPkcs11Backend backend)
    {
        RequireEdDsa(backend);
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateEd25519KeyPair(session);
            try
            {
                byte[] data = Encoding.UTF8.GetBytes("Ed25519ctx message");
                byte[] context = Encoding.UTF8.GetBytes("app-context");

                var signMech = new Mechanism(CKM.CKM_EDDSA, new CkmEddsaParams(phFlag: false, context));
                byte[] sig = session.Sign(signMech, priv, data);
                Assert.Equal(64, sig.Length);

                var verifyMech = new Mechanism(CKM.CKM_EDDSA, new CkmEddsaParams(phFlag: false, context));
                Assert.True(session.Verify(verifyMech, pub, data, sig), "Ed25519ctx round-trip should verify with the same context.");

                // A context-bound signature must not verify under a different context: the whole point of
                // Ed25519ctx is domain separation by context string.
                var wrongContextMech = new Mechanism(CKM.CKM_EDDSA,
                    new CkmEddsaParams(phFlag: false, Encoding.UTF8.GetBytes("different-context")));
                Assert.False(session.Verify(wrongContextMech, pub, data, sig), "Ed25519ctx must not verify under a different context.");
            }
            finally
            {
                session.DestroyObject(priv);
                session.DestroyObject(pub);
            }
        }
        finally
        {
            TestKeys.LogoutIfRequired(backend, session);
        }
    }

    internal static void Assert_Ed25519ph_Prehash_RoundTrips(IPkcs11Backend backend)
    {
        RequireEdDsa(backend);
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            var (pub, priv) = TestKeys.GenerateEd25519KeyPair(session);
            try
            {
                // Ed25519ph hashes the message internally (RFC 8032 §5.1); the caller supplies the
                // raw message, not a pre-computed digest.
                byte[] data = Encoding.UTF8.GetBytes("Ed25519ph message, hashed internally by the token");

                var signMech = new Mechanism(CKM.CKM_EDDSA, new CkmEddsaParams(phFlag: true));
                byte[] sig = session.Sign(signMech, priv, data);
                Assert.Equal(64, sig.Length);

                var verifyMech = new Mechanism(CKM.CKM_EDDSA, new CkmEddsaParams(phFlag: true));
                Assert.True(session.Verify(verifyMech, pub, data, sig), "Ed25519ph round-trip should verify.");

                // The same signature must not verify as a plain (non-prehash) Ed25519 signature:
                // phFlag selects a different RFC 8032 variant (Ed25519ph vs Ed25519).
                var plainMech = new Mechanism(CKM.CKM_EDDSA, new CkmEddsaParams(phFlag: false));
                Assert.False(session.Verify(plainMech, pub, data, sig), "An Ed25519ph signature must not verify as plain Ed25519.");
            }
            finally
            {
                session.DestroyObject(priv);
                session.DestroyObject(pub);
            }
        }
        finally
        {
            TestKeys.LogoutIfRequired(backend, session);
        }
    }
}
