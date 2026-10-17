using System.Buffers.Binary;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Derive;

/// <summary>
/// Backend-agnostic tests of the SP 800-108 feedback (<c>CKM_SP800_108_FEEDBACK_KDF</c>) and
/// double-pipeline (<c>CKM_SP800_108_DOUBLE_PIPELINE_KDF</c>) modes built with
/// <see cref="Sp800108KdfBuilder"/>, against a managed reference of NIST SP 800-108 §5.2 and §5.3.
/// Counter mode is covered by <c>SP800108HmacCounterKdfPkcs11TestCases</c>.
/// </summary>
/// <remarks>
/// The PRF input follows the data segments in order. The iteration variable is the chaining value: K(i-1)
/// in feedback mode (K(0) = the IV), A(i) in double-pipeline mode. A(1) is the PRF of the segments with the
/// iteration variable empty and the optional counter left out, then A(i) = PRF(A(i-1)), as NIST and NSS's
/// kbkdf.c define it. The derived value is read back (extractable, non-sensitive), so the session runs
/// under <see cref="CryptoPolicy.AllowInsecure"/>.
/// </remarks>
internal static class Sp800108ChainedKdfTestCases
{
    private static readonly byte[] BaseKey = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f");
    private static readonly byte[] Label = "kl-sp800-108-label"u8.ToArray();
    private static readonly byte[] Context = "kl-sp800-108-context"u8.ToArray();
    private static readonly byte[] Iv = Convert.FromHexString("00112233445566778899aabbccddeeff");

    // Longer than one HMAC-SHA256 block, so the chaining value is used at least once.
    private const int OutputLength = 42;

    internal static void Assert_Feedback_HmacSha256_MatchesReference(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SP800_108_FEEDBACK_KDF, CKM.CKM_SHA256_HMAC);
        byte[] actual = Derive(backend, CKM.CKM_SP800_108_FEEDBACK_KDF,
            Segments(CkmSp800108KdfParams.Feedback(CKM.CKM_SHA256_HMAC)).WithIV(Iv).Build());

        Assert.Equal(Convert.ToHexString(ReferenceFeedback()), Convert.ToHexString(actual));
    }

    internal static void Assert_DoublePipeline_HmacSha256_MatchesReference(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF, CKM.CKM_SHA256_HMAC);
        byte[] actual = DeriveDoublePipeline(backend);

        Assert.Equal(Convert.ToHexString(ReferenceDoublePipeline()), Convert.ToHexString(actual));
    }

    internal static byte[] DeriveDoublePipeline(IPkcs11Backend backend) =>
        Derive(backend, CKM.CKM_SP800_108_DOUBLE_PIPELINE_KDF, Segments(CkmSp800108KdfParams.DoublePipeline(CKM.CKM_SHA256_HMAC)).Build());

    // Iteration variable, then [i]_32, Label || 0x00 || Context, [L]_32 with L the derived length in bits.
    private static Sp800108KdfBuilder Segments(Sp800108KdfBuilder builder) =>
        builder.IterationCounter()
            .OptionalCounter()
            .ByteArray(Label)
            .ByteArray([0x00])
            .ByteArray(Context)
            .DkmLength(Sp800108DkmLengthMethod.SumOfKeys);

    private static byte[] Derive(IPkcs11Backend backend, CKM mechanism, CkmSp800108KdfParams parameters)
    {
        using var session = backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        string label = $"kl-sp800108-{Guid.NewGuid():N}";
        using var baseTemplate = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(BaseKey).Derive().OnToken(backend.SupportsTokenObjects).Build();
        using var derivedTemplate = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(OutputLength).Extractable().Sensitive(false).Build();
        using var baseKey = session.ImportKey(baseTemplate);
        try
        {
            using Pkcs11Key derived = baseKey.Derive(new Mechanism(mechanism, parameters), derivedTemplate);
            using var value = derived.GetAttributeValue(CKA.CKA_VALUE);
            byte[] bytes = value[0].GetValueAsByteArray();
            derived.Destroy();
            return bytes;
        }
        finally { baseKey.Destroy(); }
    }

    // PRF input for iteration i with the given chaining value; the counter is left out when i is null.
    private static byte[] PrfInput(byte[] chaining, uint? i)
    {
        var input = new List<byte>(chaining);
        if (i is uint counter) input.AddRange(BigEndian(counter));
        input.AddRange(Label);
        input.Add(0x00);
        input.AddRange(Context);
        input.AddRange(BigEndian(OutputLength * 8));
        return [.. input];
    }

    private static byte[] ReferenceFeedback()
    {
        var output = new List<byte>();
        byte[] k = Iv;
        for (uint i = 1; output.Count < OutputLength; i++)
        {
            k = HMACSHA256.HashData(BaseKey, PrfInput(k, i));
            output.AddRange(k);
        }
        return output.Take(OutputLength).ToArray();
    }

    internal static byte[] ReferenceDoublePipeline()
    {
        var output = new List<byte>();
        byte[] a = HMACSHA256.HashData(BaseKey, PrfInput([], null));
        for (uint i = 1; output.Count < OutputLength; i++)
        {
            if (i > 1) a = HMACSHA256.HashData(BaseKey, a);
            output.AddRange(HMACSHA256.HashData(BaseKey, PrfInput(a, i)));
        }
        return output.Take(OutputLength).ToArray();
    }

    private static byte[] BigEndian(uint value)
    {
        byte[] bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return bytes;
    }
}
