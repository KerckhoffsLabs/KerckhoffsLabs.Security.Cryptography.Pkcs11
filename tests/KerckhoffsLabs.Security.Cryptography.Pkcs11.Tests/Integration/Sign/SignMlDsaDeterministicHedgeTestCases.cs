using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// Drives <see cref="CkhHedge.CKH_DETERMINISTIC_REQUIRED"/> against a real token via
/// <c>CKM_ML_DSA</c>'s <c>CK_SIGN_ADDITIONAL_CONTEXT</c>; every other ML-DSA sign test in this suite
/// uses the default <see cref="CkhHedge.CKH_HEDGE_PREFERRED"/>. Unlike the hedged default, the effect of
/// this field can be checked directly: signing the same message twice must give byte-identical signatures.
/// </summary>
internal static class SignMlDsaDeterministicHedgeTestCases
{
    internal static void Assert_DeterministicHedge_ProducesIdenticalSignatures(IPkcs11Backend backend)
    {
        if (!backend.Supports(CKM.CKM_ML_DSA_KEY_PAIR_GEN))
            Assert.Skip("Backend does not advertise CKM_ML_DSA_KEY_PAIR_GEN.");

        using var session = backend.OpenSession();
        string label = $"mldsa-det-{Guid.NewGuid():N}";
        byte[] id = Guid.NewGuid().ToByteArray(); // 16 bytes: FreeHSM takes a CKA_ID of at most 32

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_DSA)
            .Label(label).Id(id).Verify()
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlDsa.CKP_ML_DSA_65).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_DSA)
            .Label(label).Id(id).Sign().Build();

        using var key = session.GenerateKeyPair(new Mechanism(CKM.CKM_ML_DSA_KEY_PAIR_GEN), pubTpl, privTpl);
        try
        {
            byte[] data = Encoding.UTF8.GetBytes("deterministic hedge must reproduce the same signature");

            byte[] sig1;
            try
            {
                sig1 = key.Sign(Pkcs11MechanismMap.MlDsaSign(CkhHedge.CKH_DETERMINISTIC_REQUIRED), data);
            }
            catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_MECHANISM_PARAM_INVALID)
            {
                throw new Xunit.Sdk.XunitException(
                    "The token rejected CKH_DETERMINISTIC_REQUIRED as a malformed CK_SIGN_ADDITIONAL_CONTEXT block.", ex);
            }
            catch (Pkcs11Exception ex)
            {
                Assert.Skip($"The token will not run deterministic ML-DSA signing ({ex.ReturnValue}).");
                throw; // Assert.Skip always throws; xunit.v3.assert 4.0.1 lacks [DoesNotReturn].
            }

            byte[] sig2 = key.Sign(Pkcs11MechanismMap.MlDsaSign(CkhHedge.CKH_DETERMINISTIC_REQUIRED), data);
            Assert.Equal(sig1, sig2);

            Assert.True(key.Verify(Pkcs11MechanismMap.MlDsaSign(CkhHedge.CKH_DETERMINISTIC_REQUIRED), data, sig1));
        }
        finally
        {
            try { key.Destroy(); } catch (Pkcs11Exception) { /* best-effort cleanup */ }
        }
    }
}
