using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// DSAPkcs11 is intentionally [Obsolete] (DSA is disallowed by FIPS 186-5); exercising it here is deliberate.
#pragma warning disable KLPKCS11006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic DSAPkcs11 tests. A keypair is generated on the token from a fixed FIPS 186-3
/// 2048/256 domain (p, q, g); sign/verify and parameter export run, with signatures cross-checked
/// against the BCL <see cref="DSA"/> from the exported public key. Every CKM_DSA* operation is gated at
/// the mechanism layer (DSA is disallowed), so the functional cases opt into the AllowInsecure policy. Cases skip
/// where the backend does not implement DSA (e.g. opencryptoki, built -DNODSA).
/// </summary>
internal static class DSAPkcs11TestCases
{
    // macOS BCL (DSASecurityTransforms) can't import/verify a 2048-bit DSA key — DSA.Create(2048)
    // throws — so the BCL cross-check can't run there even though SoftHSM signs fine.
    private static readonly bool DsaSupported = ProbeDsa();

    private static bool ProbeDsa()
    {
        try
        {
            using var d = DSA.Create(2048);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    // Fixed 2048-bit prime / 256-bit subprime DSA domain parameters (generated with the BCL).
    private static readonly byte[] P = Convert.FromHexString(
        "F2936B4861E422E0CA0A75FD0F4E5F4771302F0B930048297ECF2B58D586436C79D6A4E2D82A8DB56B4C73094FEB91FC204FA0CF01D0EEF11C669E8BC793A9EB5DEA5B7CC8A8A30623539FA2869CBF16D6DDCD087AFEE2CC22A638B0740B7CA00A7835A28A886FE1C3342A1A84FED1F1D2BD2FA9979EA93497A81D11622AE005B31DAC41740C1C22946D26E48CCEFD03C058A74B9089D055BE2846F12B010B08BC07C40595508BB575A8B4180C9ED2BC4A138B896AAF4DFBCC6B7F2E684E612CCA77AD20130021B83AE12151CA226D33E392A076E5F3825974CA8922CC0EB172F1FC312CE31F92F615E7C92ED747F9B3455883C75FEA4C2B4067B483185F90C3");
    private static readonly byte[] Q = Convert.FromHexString(
        "BCFFB514829FFE01A3E790321F7551F74E298660CDC9B5E215F9EEE31025D20B");
    private static readonly byte[] G = Convert.FromHexString(
        "74D6E59535228FFB244180ADBE81BE791C7C86A5B7E3E40D9E80ED9EC767F4E781B8B2359BF9DBE520D7B33B157A92994CFC523AD701C01715A9A67219802FF05E581B5DAB2B14BC4CBEBAEF6CD74A35361A03B8BAE5C7D5E708DEE143E3CA745D1DED52AF461175FD02F2A7BD7C159885707B33540748DAD3B2ADF31C24E532F8BC20663A8FF293D137AA2326C63BCAB9835F716284A5E09CEEF50D8F0B8E33F258E662BC9F6BA4AF996F30898F27CCCF4377A71547B7FF3FF56310D5194766B4BBCDDC5D11928A46BDA6E57BABAA905F8B7184B3906F1AECE20F2B5A7016422B5C52012B0F21EAC655054FAC6F1A56741BB7FDFED40A8B524314EFF8E94B93");

    private static Pkcs11Session OpenSession(IPkcs11Backend backend) =>
        backend.OpenSession();

    private static void DestroyByLabel(Pkcs11Session session, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in session.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }

    // Generates a DSA key pair on the token from the fixed domain parameters and hands DSAPkcs11 to the
    // body. DSA is FIPS-186-5-disallowed and every CKM_DSA* sign/verify is gated at the mechanism layer,
    // so the functional overload opts into the AllowInsecure policy; the gated-by-default test passes false. Skips
    // where the backend does not implement DSA.
    private static void WithDsa(IPkcs11Backend backend, Action<DSAPkcs11> body)
        => WithDsa(backend, allowInsecure: true, (_, dsa) => body(dsa));

    private static void WithDsa(IPkcs11Backend backend, bool allowInsecure, Action<Pkcs11Session, DSAPkcs11> body)
    {
        if (!backend.Supports(CKM.CKM_DSA))
            Assert.Skip("Backend does not advertise CKM_DSA.");

        using var session = OpenSession(backend);
        string label = $"dsa-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_DSA)
            .Label(label).Id(id).Verify()
            .Attribute(CKA.CKA_PRIME, P)
            .Attribute(CKA.CKA_SUBPRIME, Q)
            .Attribute(CKA.CKA_BASE, G)
            .Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_DSA)
            .Label(label).Id(id).Sign().Build();

        // SecureOnly documents CKM_DSA_KEY_PAIR_GEN as refused, so key generation always opts in; the
        // body's own lease below decides whether the sign/verify under test does.
        Pkcs11Key generated;
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
        {
#pragma warning disable KLPKCS11009 // DSA key generation is the set-up under test
            generated = session.GenerateKeyPair(new Mechanism(CKM.CKM_DSA_KEY_PAIR_GEN), pubTpl, privTpl);
#pragma warning restore KLPKCS11009
        }

        using var key = generated;
        using IDisposable? insecure = allowInsecure ? session.UsePolicy(CryptoPolicy.AllowInsecure) : null;
        try
        {
            using var dsa = new DSAPkcs11(key);
            body(session, dsa);
        }
        finally
        {
            try { key.Destroy(); } catch { /* best-effort */ }
        }
    }

    internal static void Assert_Ctor_NonDsaKey_Throws(IPkcs11Backend backend)
    {
        using var session = OpenSession(backend);
        string label = $"dsa-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build())
        {
            using var _ = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = session.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new DSAPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(session, label); }
    }

    internal static void Assert_SignVerifyData_RoundTrips(IPkcs11Backend backend) =>
        WithDsa(backend, dsa =>
        {
            byte[] data = Encoding.UTF8.GetBytes("dsa round trip");
            byte[] sig = dsa.SignData(data, HashAlgorithmName.SHA256);
            Assert.True(dsa.VerifyData(data, sig, HashAlgorithmName.SHA256));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(dsa.VerifyData(tampered, sig, HashAlgorithmName.SHA256));
        });

    // DSA is gated at the mechanism layer: signing is refused without the AllowInsecure policy, even though
    // SoftHSM advertises CKM_DSA_SHA256. (Key generation opts in on its own, so this still sets up.)
    internal static void Assert_SignData_GatedByDefault_Throws(IPkcs11Backend backend) =>
        WithDsa(backend, allowInsecure: false, (_, dsa) =>
            Assert.Throws<CryptoPolicyViolationException>(
                () => dsa.SignData(Encoding.UTF8.GetBytes("x"), HashAlgorithmName.SHA256)));

    // Vary the hash on the token key. These byte[] overloads hash before raw CKM_DSA: on the managed side,
    // or, for SHA-224, which the BCL lacks, with the token's CKM_SHA224 digest.
    internal static void Assert_SignVerifyData_AcrossHashAlgorithms_RoundTrips(IPkcs11Backend backend, string hashName)
    {
        if (hashName == "SHA224")
            backend.RequireMechanisms(CKM.CKM_SHA224);
        WithDsa(backend, dsa =>
        {
            var hash = new HashAlgorithmName(hashName);
            byte[] data = Encoding.UTF8.GetBytes($"dsa over {hashName}");
            byte[] sig = dsa.SignData(data, hash);
            Assert.True(dsa.VerifyData(data, sig, hash));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(dsa.VerifyData(tampered, sig, hash));
        });
    }

    // DSA.SignData(byte[], HashAlgorithmName) is a NON-virtual convenience overload with no Span-input
    // counterpart returning byte[] — it never calls TrySignData, and passing byte[] arguments to
    // VerifyData picks the non-virtual byte[] overload over the virtual span one DSAPkcs11 overrides.
    // Assert_SignVerifyData_AcrossHashAlgorithms_RoundTrips above (byte[] arguments throughout) never
    // exercises DSAPkcs11's own TrySignData / VerifyData override / SignDataInternal — only the base
    // class's generic-hash-then-CreateSignature(hash) path. This drives the actual combined-mechanism
    // code this adapter exists for, via TrySignData directly and VerifyData with arguments explicitly
    // typed as ReadOnlySpan<byte> so the compiler picks the virtual overload.
    internal static void Assert_TrySignData_VerifyDataSpan_RoundTrips_AndRejectsTampering(IPkcs11Backend backend, string hashName)
    {
        // Without CKM_DSA_SHA224 (NSS before 3.52 does not advertise it) the adapter hashes before raw
        // CKM_DSA, and SHA-224, which the BCL lacks, needs the token's CKM_SHA224 digest for that.
        if (hashName == "SHA224" && !backend.Supports(CKM.CKM_DSA_SHA224))
            backend.RequireMechanisms(CKM.CKM_SHA224);
        WithDsa(backend, dsa =>
        {
            var hash = new HashAlgorithmName(hashName);
            byte[] data = Encoding.UTF8.GetBytes($"span-based dsa round trip over {hashName}");
            Span<byte> destination = new byte[256];

            Assert.True(dsa.TrySignData(data, destination, hash, out int bytesWritten));
            byte[] sig = destination[..bytesWritten].ToArray();

            Assert.True(dsa.VerifyData((ReadOnlySpan<byte>)data, (ReadOnlySpan<byte>)sig, hash));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(dsa.VerifyData((ReadOnlySpan<byte>)tampered, (ReadOnlySpan<byte>)sig, hash));

            byte[] badSig = [.. sig];
            badSig[0] ^= 0xFF;
            Assert.False(dsa.VerifyData((ReadOnlySpan<byte>)data, (ReadOnlySpan<byte>)badSig, hash));
        });
    }

    internal static void Assert_SignData_VerifiesUnderBclWithExportedPublicKey(IPkcs11Backend backend)
    {
        if (!DsaSupported)
            Assert.Skip("Platform BCL cannot import a 2048-bit DSA key (macOS DSASecurityTransforms).");

        WithDsa(backend, dsa =>
        {
            byte[] data = Encoding.UTF8.GetBytes("interop with the BCL");
            byte[] sig = dsa.SignData(data, HashAlgorithmName.SHA256);

            // Export the token's public parameters and verify the token signature with the BCL.
            DSAParameters pub = dsa.ExportParameters(includePrivateParameters: false);
            using var bcl = DSA.Create();
            bcl.ImportParameters(pub);
            Assert.True(bcl.VerifyData(data, sig, HashAlgorithmName.SHA256));
        });
    }

    internal static void Assert_CreateSignature_VerifySignature_OverHash_RoundTrips(IPkcs11Backend backend) =>
        WithDsa(backend, dsa =>
        {
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes("hash to sign"));
            byte[] sig = dsa.CreateSignature(hash);
            Assert.True(dsa.VerifySignature(hash, sig));
            Assert.Equal(2 * Q.Length, sig.Length); // P1363 r‖s, each q-sized
        });

    // Every verification overload that takes a DSASignatureFormat ends in the adapter's VerifySignatureCore:
    // P1363 goes to the token as is, DER is converted to r‖s first.
    internal static void Assert_VerifyWithSignatureFormat_AcceptsBothFormats_AndRejectsTampering(IPkcs11Backend backend, DSASignatureFormat format) =>
        WithDsa(backend, dsa =>
        {
            var sha256 = HashAlgorithmName.SHA256;
            byte[] data = Encoding.UTF8.GetBytes($"dsa verify in {format}");
            byte[] hash = SHA256.HashData(data);
            byte[] sig = dsa.SignData(data, sha256, format);

            Assert.True(dsa.VerifyData(data, sig, sha256, format));
            Assert.True(dsa.VerifyData(data, 0, data.Length, sig, sha256, format));
            Assert.True(dsa.VerifyData((ReadOnlySpan<byte>)data, sig, sha256, format));
            using (var stream = new MemoryStream(data))
                Assert.True(dsa.VerifyData(stream, sig, sha256, format));
            Assert.True(dsa.VerifySignature(hash, sig, format));
            Assert.True(dsa.VerifySignature((ReadOnlySpan<byte>)hash, sig, format));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(dsa.VerifyData(tampered, sig, sha256, format));

            // The last byte is s's last in either format, so the DER encoding stays well formed.
            byte[] badSig = [.. sig];
            badSig[^1] ^= 0xFF;
            Assert.False(dsa.VerifyData(data, badSig, sha256, format));
        });

    // Every entry point that takes a hash name and signs, in the format given; the ones without a format
    // sign in P1363. With SHA-224 they all hash with the token's CKM_SHA224 digest, except TrySignData
    // without a format, which signs with CKM_DSA_SHA224 when the token has it.
    private static IEnumerable<byte[]> Sha224Signatures(DSAPkcs11 dsa, byte[] data, DSASignatureFormat format)
    {
        var sha224 = new HashAlgorithmName("SHA224");
        byte[] destination = new byte[256];

        yield return dsa.SignData(data, sha224, format);
        yield return dsa.SignData(data, 0, data.Length, sha224, format);
        using (var stream = new MemoryStream(data))
            yield return dsa.SignData(stream, sha224, format);
        Assert.True(dsa.TrySignData(data, destination, sha224, format, out int written));
        yield return destination[..written];

        if (format != DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
            yield break;
        yield return dsa.SignData(data, sha224);
        yield return dsa.SignData(data, 0, data.Length, sha224);
        using (var stream = new MemoryStream(data))
            yield return dsa.SignData(stream, sha224);
        Assert.True(dsa.TrySignData(data, destination, sha224, out written));
        yield return destination[..written];
    }

    // Every entry point that takes a hash name and verifies, in the format given, answering whether all of
    // them accept the signature and whether any does; the ones without a format take P1363. VerifyData(span)
    // without a format verifies with CKM_DSA_SHA224 when the token has it.
    private static (bool All, bool Any) VerifySha224(DSAPkcs11 dsa, byte[] data, byte[] signature, DSASignatureFormat format)
    {
        var sha224 = new HashAlgorithmName("SHA224");
        List<bool> verdicts =
        [
            dsa.VerifyData(data, signature, sha224, format),
            dsa.VerifyData(data, 0, data.Length, signature, sha224, format),
            dsa.VerifyData((ReadOnlySpan<byte>)data, signature, sha224, format),
        ];
        using (var stream = new MemoryStream(data))
            verdicts.Add(dsa.VerifyData(stream, signature, sha224, format));

        if (format == DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
        {
            verdicts.Add(dsa.VerifyData(data, signature, sha224));
            verdicts.Add(dsa.VerifyData(data, 0, data.Length, signature, sha224));
            verdicts.Add(dsa.VerifyData((ReadOnlySpan<byte>)data, (ReadOnlySpan<byte>)signature, sha224));
            using var stream = new MemoryStream(data);
            verdicts.Add(dsa.VerifyData(stream, signature, sha224));
        }
        return (verdicts.TrueForAll(v => v), verdicts.Contains(true));
    }

    // The BCL has no SHA-224, so the adapter hashes it with the token's CKM_SHA224 digest: every overload
    // that takes a hash name signs and verifies with it, in either format, and they agree with each other
    // (and with CKM_DSA_SHA224, where the token has it).
    internal static void Assert_Sha224_EveryOverload_RoundTrips_AndRejectsTampering(IPkcs11Backend backend, DSASignatureFormat format)
    {
        backend.RequireMechanisms(CKM.CKM_SHA224);
        WithDsa(backend, dsa =>
        {
            byte[] data = Encoding.UTF8.GetBytes($"dsa over SHA-224 in {format}");
            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;

            foreach (byte[] sig in Sha224Signatures(dsa, data, format))
            {
                Assert.True(VerifySha224(dsa, data, sig, format).All);
                Assert.False(VerifySha224(dsa, tampered, sig, format).Any);

                // The last byte is s's last in either format, so the DER encoding stays well formed.
                byte[] badSig = [.. sig];
                badSig[^1] ^= 0xFF;
                Assert.False(VerifySha224(dsa, data, badSig, format).Any);
            }
        });
    }

    // dsa_2048_224_sha224_test.json from C2SP/wycheproof, tcId 2 ("valid"): a DER signature over
    // "123400" under a 2048/224 public key, which no token-generated key could stand in for.
    private static readonly byte[] WycheproofP = Convert.FromHexString(
        "8F7935D9B9AAE9BFABED887ACF4951B6F32EC59E3BAF3718E8EAC4961F3EFD3606E74351A9C4183339B809E7C2AE1C539BA7475B85D011ADB8B47987754984695CAC0E8F14B3360828A22FFA27110A3D62A993453409A0FE696C4658F84BDD20819C3709A01057B195ADCD00233DBA5484B6291F9D648EF883448677979CEC04B434A6AC2E75E9985DE23DB0292FC1118C9FFA9D8181E7338DB792B730D7B9E349592F68099872153915EA3D6B8B4653C633458F803B32A4C2E0F27290256E4E3F8A3B0838A1C450E4E18C1A29A37DDF5EA143DE4B66FF04903ED5CF1623E158D487C608E97F211CD81DCA23CB6E380765F822E342BE484C05763939601CD667");
    private static readonly byte[] WycheproofQ = Convert.FromHexString(
        "BAF696A68578F7DFDEE7FA67C977C785EF32B233BAE580C0BCD5695D");
    private static readonly byte[] WycheproofG = Convert.FromHexString(
        "16A65C58204850704E7502A39757040D34DA3A3478C154D4E4A5C02D242EE04F96E61E4BD0904ABDAC8F37EEB1E09F3182D23C9043CB642F88004160EDF9CA09B32076A79C32A627F2473E91879BA2C4E744BD2081544CB55B802C368D1FA83ED489E94E0FA0688E32428A5C78C478C68D0527B71C9A3ABB0B0BE12C44689639E7D3CE74DB101A65AA2B87F64C6826DB3EC72F4B5599834BB4EDB02F7C90E9A496D3A55D535BEBFC45D4F619F63F3DEDBB873925C2F224E07731296DA887EC1E4748F87EFB5FDEB75484316B2232DEE553DDAF02112B0D1F02DA30973224FE27AEDA8B9D4B2922D9BA8BE39ED9E103A63C52810BC688B7E2ED4316E1EF17DBDE");
    private static readonly byte[] WycheproofY = Convert.FromHexString(
        "1E77F842B1AE0FCD9929D394161D41E14614FF7507A9A31F4A1F14D22E2A627A1F4E596624883F1A5B168E9425146F22D5F6EE28757414714BB994BA1129F015D6E04A717EDF9B530A5D5CAB94F14631E8B4CF79AEB358CC741845553841E8AC461630E804A62F43676BA6794AF66899C377B869EA612A7B9FE6611AA96BE52EB8B62C979117BBBCCA8A7EC1E1FFAB1C7DFCFC7048700D3AE3858136E897701D7C2921B5DFEF1D1F897F50D96CA1B5C2EDC58CADA18919E35642F0807EEBFA00C99A32F4D095C3188F78ED54711BE0325C4B532AECCD6540A567C327225440EA15319BDE06510479A1861799E25B57DECC73C036D75A0702BD373CA231349931");
    private static readonly byte[] WycheproofMessage = Convert.FromHexString("313233343030");
    private static readonly byte[] WycheproofDerSignature = Convert.FromHexString(
        "303D021D00A545D62D6E336775FB6A9B8495721646A54BD8C6173FC0A2295A1B7B021C068259CF902E5D55EB26E7BF850A82D40FC5456B3A902679612EA4A8");

    // The vector verifies through every overload that takes SHA-224, as DER and converted to r‖s, and a
    // tampered message or signature does not.
    internal static void Assert_Sha224_WycheproofVector_Verifies_AndTamperedDoesNot(IPkcs11Backend backend)
    {
        if (!backend.Supports(CKM.CKM_DSA))
            Assert.Skip("Backend does not advertise CKM_DSA.");
        backend.RequireMechanisms(CKM.CKM_SHA224);

        using var session = OpenSession(backend);
        using var template = ObjectTemplate.ForPublicKey(CKK.CKK_DSA)
            .Label($"dsa-wycheproof-{Guid.NewGuid():N}").Verify().OnToken(false)
            .Attribute(CKA.CKA_PRIME, WycheproofP)
            .Attribute(CKA.CKA_SUBPRIME, WycheproofQ)
            .Attribute(CKA.CKA_BASE, WycheproofG)
            .Attribute(CKA.CKA_VALUE, WycheproofY)
            .Build();
        using var key = session.ImportKey(template);
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        try
        {
            using var dsa = new DSAPkcs11(key);
            const int FieldLength = 28;
            byte[] der = WycheproofDerSignature;
            byte[] ieee = [.. der.AsSpan(5, FieldLength), .. der.AsSpan(der.Length - FieldLength)];
            Assert.Equal(DerSignature(ieee[..FieldLength], ieee[FieldLength..]), der);

            byte[] tampered = [.. WycheproofMessage];
            tampered[^1] ^= 0x01;
            byte[] badDer = [.. der];
            badDer[^1] ^= 0x01;
            byte[] badIeee = [.. ieee];
            badIeee[^1] ^= 0x01;

            Assert.True(VerifySha224(dsa, WycheproofMessage, der, DSASignatureFormat.Rfc3279DerSequence).All);
            Assert.True(VerifySha224(dsa, WycheproofMessage, ieee, DSASignatureFormat.IeeeP1363FixedFieldConcatenation).All);
            Assert.False(VerifySha224(dsa, tampered, der, DSASignatureFormat.Rfc3279DerSequence).Any);
            Assert.False(VerifySha224(dsa, tampered, ieee, DSASignatureFormat.IeeeP1363FixedFieldConcatenation).Any);
            Assert.False(VerifySha224(dsa, WycheproofMessage, badDer, DSASignatureFormat.Rfc3279DerSequence).Any);
            Assert.False(VerifySha224(dsa, WycheproofMessage, badIeee, DSASignatureFormat.IeeeP1363FixedFieldConcatenation).Any);
        }
        finally
        {
            try { key.Destroy(); } catch { /* best-effort */ }
        }
    }

    // A malformed DER signature, or one whose r does not fit q, does not verify, as for the BCL; nor does an
    // r‖s signature of the wrong length, on any verification path, which tokens report in different ways
    // (CKR_SIGNATURE_LEN_RANGE; NSS: CKR_ARGUMENTS_BAD) and the adapter therefore checks itself.
    internal static void Assert_VerifyWithSignatureFormat_MalformedSignature_ReturnsFalse(IPkcs11Backend backend) =>
        WithDsa(backend, dsa =>
        {
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes("malformed signatures"));
            byte[] ieee = dsa.CreateSignature(hash);
            byte[] der = DerSignature(ieee[..Q.Length], ieee[Q.Length..]);
            Assert.True(dsa.VerifySignature(hash, der, DSASignatureFormat.Rfc3279DerSequence));

            byte[] r = ieee[..Q.Length];
            byte[] s = ieee[Q.Length..];
            byte[][] notVerifying =
            [
                [],
                der[..^1],
                [.. der, 0x00],
                [0x04, .. der[1..]],
                // r one and two bytes longer than q, without the zero that only a set high bit needs.
                DerSignature([0x01, .. r], s),
                DerSignature([0x01, 0x01, .. r], s),
                // Well formed, but another r: shorter than q, and with its high bit set.
                DerSignature([0x05], s),
                DerSignature([(byte)(r[0] >= 0x80 ? r[0] ^ 0x01 : 0x80), .. r[1..]], s),
            ];
            foreach (byte[] signature in notVerifying)
                Assert.False(dsa.VerifySignature(hash, signature, DSASignatureFormat.Rfc3279DerSequence));

            Assert.False(dsa.VerifySignature(hash, ieee[..^1], DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            Assert.False(dsa.VerifySignature(hash, (byte[])[.. ieee, 0x00], DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            Assert.False(dsa.VerifySignature(hash, ieee[..^1]));
            Assert.False(dsa.VerifySignature(hash, (byte[])[.. ieee, 0x00]));

            byte[] data = Encoding.UTF8.GetBytes("a signature of the wrong length");
            byte[] sig = dsa.SignData(data, HashAlgorithmName.SHA256);
            Assert.False(dsa.VerifyData(data.AsSpan(), sig.AsSpan(0, sig.Length - 1), HashAlgorithmName.SHA256));
            Assert.False(dsa.VerifyData(data, (byte[])[.. sig, 0x00], HashAlgorithmName.SHA256));
        });

    // Dss-Sig-Value { r, s } over the given big-endian values, taken as unsigned.
    internal static byte[] DerSignature(byte[] r, byte[] s)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteIntegerUnsigned(Minimal(r));
            writer.WriteIntegerUnsigned(Minimal(s));
        }
        return writer.Encode();

        // An r‖s half is q's width, so about one in 256 starts with a zero byte, which WriteIntegerUnsigned
        // refuses as redundant.
        static ReadOnlySpan<byte> Minimal(ReadOnlySpan<byte> value)
        {
            while (value is [0, _, ..])
                value = value[1..];
            return value;
        }
    }

    internal static void Assert_ExportParameters_ReturnsProvidedDomain(IPkcs11Backend backend) =>
        WithDsa(backend, dsa =>
        {
            DSAParameters pub = dsa.ExportParameters(includePrivateParameters: false);
            Assert.Equal(P, pub.P);
            Assert.Equal(Q, pub.Q);
            Assert.Equal(G, pub.G);
            Assert.NotNull(pub.Y);
            Assert.Equal(P.Length, pub.Y!.Length);
            Assert.Null(pub.X); // never exports the private value
        });

    internal static void Assert_ExportParameters_Private_ThrowsInsecure(IPkcs11Backend backend) =>
        WithDsa(backend, dsa =>
            Assert.Throws<CryptoPolicyViolationException>(() => dsa.ExportParameters(includePrivateParameters: true)));

    internal static void Assert_ImportParameters_NotSupported(IPkcs11Backend backend) =>
        WithDsa(backend, dsa =>
            Assert.Throws<NotSupportedException>(() => dsa.ImportParameters(new DSAParameters { P = P, Q = Q, G = G })));
}
