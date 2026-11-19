using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Vectors;
using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Vectors.WycheproofVectors;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Adapters;

/// <summary>
/// ML-DSA (FIPS 204) verification against the Wycheproof <c>mldsa_{44,65,87}_verify_test.json</c> vectors (see
/// <see cref="WycheproofVectors"/>). Where the NIST ACVP cases in <see cref="AcvpKnownAnswerTestCases"/> are a valid
/// signature and a few modified ones, these aim at what verifiers get wrong. Among them are signatures one byte too
/// short or long and public keys likewise, hints out of order, repeated, or overflowing ω, and z one past its infinity
/// norm. Others are a challenge hash starting with a zero byte (a strcmp-style comparison), contexts of 256 bytes
/// and their wrong length encodings, and valid signatures on the boundaries of Decompose, UseHint and the rejection
/// sampling of the matrix expansion. pkcs11-check 0.3.0's refreshed Wycheproof pin regenerated these vectors
/// (https://github.com/mingulov/pkcs11-check, sources.toml).
/// </summary>
/// <remarks>
/// <para>
/// One case per parameter set runs every vector in one session and lists every one with the wrong verdict, by its
/// tcId and comment. A valid signature must verify. An invalid one must be refused: <c>C_Verify</c> answers
/// <c>CKR_SIGNATURE_INVALID</c> or <c>CKR_SIGNATURE_LEN_RANGE</c>; a public key of the wrong length may instead be
/// refused when it is imported (<c>CKR_ATTRIBUTE_VALUE_INVALID</c> or <c>CKR_KEY_SIZE_RANGE</c>); and a context over
/// 255 bytes is refused by <see cref="CkmPqcSignParams"/> before it reaches the token. Any other return code is a
/// wrong answer too.
/// </para>
/// <para>
/// A backend that gets a vector wrong declares it in its wrapper, with the reason: the vector is then left out, and
/// a declared vector that the backend now gets right fails, so the declaration goes. A vector with a context is left
/// out on a backend that takes none (<see cref="IPkcs11Backend.SupportsPqcSignContext"/>).
/// </para>
/// </remarks>
internal static class WycheproofMlDsaTestCases
{
    public static TheoryData<string> ParameterSets => ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];

    private static readonly CKR[] WrongLengthKeyRefusals = [CKR.CKR_ATTRIBUTE_VALUE_INVALID, CKR.CKR_KEY_SIZE_RANGE];

    // declared gives the reason a backend gets a vector wrong, or null when it gets it right.
    internal static void Assert_MlDsa_Verification_Wycheproof(
        IPkcs11Backend backend, string parameterSet, Func<MlDsaVerification, string?>? declared = null)
    {
        backend.RequireMechanism(CKM.CKM_ML_DSA);
        ulong set = (ulong)AcvpKnownAnswerTestCases.MlDsaParameterSet(parameterSet);
        List<MlDsaVerification> vectors = [.. MlDsaVerifications.Where(v => v.ParameterSet == parameterSet)];
        Assert.NotEmpty(vectors);

        List<string> wrong = [];
        int run = 0;
        AcvpKnownAnswerTestCases.WithSession(backend, session =>
        {
            // A backend that takes no ML-DSA context runs only the vectors without one.
            foreach (MlDsaVerification v in vectors.Where(c => c.Context.Length == 0 || backend.SupportsPqcSignContext))
            {
                run++;
                string outcome = Verify(session, set, v);
                bool right = outcome == (v.Valid ? Verified : Refused);
                string? because = declared?.Invoke(v);
                if (because is not null && right)
                    wrong.Add($"tcId {v.TcId} ({v.Comment}): now gets the right verdict; drop its declaration (\"{because}\").");
                else if (because is null && !right)
                    wrong.Add($"tcId {v.TcId} ({v.Comment}, {v.Result}): {outcome}.");
            }
        });

        Assert.True(run > 0, $"No {parameterSet} vector ran.");
        Assert.True(wrong.Count == 0,
            $"{wrong.Count} of {run} Wycheproof {parameterSet} vectors got the wrong verdict:{Environment.NewLine}" +
            string.Join(Environment.NewLine, wrong));
    }

    private const string Verified = "verified";
    private const string Refused = "refused";

    private static string Verify(Pkcs11SessionCore session, ulong parameterSet, MlDsaVerification v)
    {
        Mechanism mechanism;
        try
        {
            mechanism = new Mechanism(CKM.CKM_ML_DSA, new CkmPqcSignParams(context: v.Context));
        }
        catch (ArgumentException) when (v.Context.Length > 255)
        {
            return Refused; // FIPS 204 caps the context at 255 bytes; the library refuses a longer one itself.
        }

        ObjectHandle pub;
        try
        {
            pub = AcvpKnownAnswerTestCases.ImportPublicKey(session, CKK.CKK_ML_DSA, parameterSet, v.PublicKey);
        }
        catch (Pkcs11Exception ex) when (v.Flags.Contains("IncorrectPublicKeyLength") && WrongLengthKeyRefusals.Contains(ex.ReturnValue))
        {
            return Refused;
        }
        catch (Pkcs11Exception ex)
        {
            return $"importing the public key answered {ex.ReturnValue}";
        }

        try
        {
            return session.Verify(mechanism, pub, v.Message, v.Signature) ? Verified : Refused;
        }
        catch (Pkcs11Exception ex)
        {
            return $"C_Verify answered {ex.ReturnValue}";
        }
        finally { session.DestroyObject(pub); }
    }
}
