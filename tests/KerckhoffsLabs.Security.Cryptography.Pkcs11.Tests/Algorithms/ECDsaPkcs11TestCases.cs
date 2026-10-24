using System.Security.Cryptography;
using BclECCurve = System.Security.Cryptography.ECCurve;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic ECDsaPkcs11 tests: sign/verify (byte[] + span overloads) cross-verified under the
/// BCL, raw SignHash/VerifyHash, public-parameter export, and the unsupported BCL surface. Curve is a
/// parameter so each wrapper supplies the curves its backend implements (SoftHSM: P-256/384/521;
/// opencryptoki: P-256). Cases skip where the backend lacks EC key-pair generation + ECDSA.
/// </summary>
internal static class ECDsaPkcs11TestCases
{
    // Curve under test -> (CKA_EC_PARAMS OID, hash paired with the curve, expected exported OID value).
    private static (byte[] oid, HashAlgorithmName hash, string? expectedOidValue) Spec(string curve) => curve switch
    {
        "P-256" => (TestKeys.EcP256Oid, HashAlgorithmName.SHA256, BclECCurve.NamedCurves.nistP256.Oid.Value),
        "P-384" => (TestKeys.EcP384Oid, HashAlgorithmName.SHA384, BclECCurve.NamedCurves.nistP384.Oid.Value),
        "P-521" => (TestKeys.EcP521Oid, HashAlgorithmName.SHA512, BclECCurve.NamedCurves.nistP521.Oid.Value),
        _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "Unknown EC curve."),
    };

    private static Pkcs11Session OpenSession(IPkcs11Backend backend) =>
        backend.OpenSession();

    private static Pkcs11Key GenerateEcKey(Pkcs11Session session, byte[] ecOid)
    {
        string label = $"ec-prov-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label(label).Id(id).Verify().EcParams(ecOid).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Label(label).Id(id).Sign().Build();

        return session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pubTpl, privTpl);
    }

    private static void DestroyByLabel(Pkcs11Session session, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in session.FindKeys(filter))
        {
            k.Destroy();
            k.Dispose();
        }
    }

    // Generates an EC key pair for the curve, wraps it as ECDsaPkcs11, runs the body with the
    // curve-matched hash, then destroys the key. Skips where the backend lacks EC keygen / ECDSA.
    private static void WithEcDsa(IPkcs11Backend backend, string curve, Action<ECDsaPkcs11, HashAlgorithmName> body) =>
        WithEcDsa(backend, curve, ec => body(ec, Spec(curve).hash));

    private static void WithEcDsa(IPkcs11Backend backend, string curve, Action<ECDsaPkcs11> body) =>
        WithEcDsa(backend, curve, (_, ec) => body(ec));

    // Overload exposing the session for tests that need UsePolicy(CryptoPolicy.AllowInsecure) (e.g. SHA-224/SHA-1).
    private static void WithEcDsa(IPkcs11Backend backend, string curve, Action<Pkcs11Session, ECDsaPkcs11> body)
    {
        if (!backend.Supports(CKM.CKM_EC_KEY_PAIR_GEN) || !backend.Supports(CKM.CKM_ECDSA))
            Assert.Skip("Backend does not advertise CKM_EC_KEY_PAIR_GEN + CKM_ECDSA.");

        var (oid, _, _) = Spec(curve);
        using var session = OpenSession(backend);
        using var key = GenerateEcKey(session, oid);
        try
        {
            using var ec = new ECDsaPkcs11(key);
            body(session, ec);
        }
        finally
        {
            try { key.Destroy(); } catch { /* best-effort cleanup */ }
        }
    }

    // A token reports a signature of the wrong length as CKR_SIGNATURE_LEN_RANGE, which PKCS#11 defines as
    // invalid solely because of its length: like the BCL, the signature does not verify, rather than throwing.
    // NSS 3.51 reports it as CKR_DATA_LEN_RANGE instead, a code PKCS#11 reserves for input data of a bad
    // length, which the library does not take as a verdict; on that token the call may throw it.
    internal static void Assert_VerifyData_SignatureOfTheWrongLength_ReturnsFalse(
        IPkcs11Backend backend, bool tokenReportsItAsDataLenRange = false) =>
        WithEcDsa(backend, "P-256", (ec, hash) =>
        {
            byte[] data = Encoding.UTF8.GetBytes("a signature of the wrong length");
            byte[] sig = ec.SignData(data, hash);

            AssertDoesNotVerify(() => ec.VerifyData(data.AsSpan(), sig.AsSpan(0, sig.Length - 1), hash), tokenReportsItAsDataLenRange);
            AssertDoesNotVerify(() => ec.VerifyData(data.AsSpan(), [.. sig, 0], hash), tokenReportsItAsDataLenRange);
            AssertDoesNotVerify(() => ec.VerifyHash(SHA256.HashData(data), sig[..^1]), tokenReportsItAsDataLenRange);
        });

    private static void AssertDoesNotVerify(Func<bool> verify, bool dataLenRangeAllowed)
    {
        try
        {
            Assert.False(verify());
        }
        catch (Pkcs11Exception e) when (dataLenRangeAllowed && e.ReturnValue == CKR.CKR_DATA_LEN_RANGE)
        {
            // The token's misreport of a signature of the wrong length; see above.
        }
    }

    internal static void Assert_Ctor_NonEcKey_Throws(IPkcs11Backend backend)
    {
        using var session = OpenSession(backend);
        string label = $"ec-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build())
        {
            using var _ = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = session.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new ECDsaPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(session, label); }
    }

    // Curve × hash matrix: ECDSA signs whatever digest it is handed, so curve and digest are
    // independent. Cross-verify each signature under the BCL from the exported public key (raw r‖s).
    internal static void Assert_SignVerifyData_CurveHashMatrix_RoundTrips(IPkcs11Backend backend, string curve, string hashName) =>
        WithEcDsa(backend, curve, ec =>
        {
            var hash = new HashAlgorithmName(hashName);
            byte[] data = Encoding.UTF8.GetBytes($"ecdsa {curve}/{hashName}");
            byte[] sig = ec.SignData(data, hash);
            Assert.True(ec.VerifyData(data, sig, hash));

            using var bcl = ECDsa.Create(ec.ExportParameters(includePrivateParameters: false));
            Assert.True(bcl.VerifyData(data, sig, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(ec.VerifyData(tampered, sig, hash));
        });

    internal static void Assert_TrySignData_Span_VerifyData_Span_RoundTrips(IPkcs11Backend backend, string curve) =>
        WithEcDsa(backend, curve, (ec, hash) =>
        {
            byte[] data = Encoding.UTF8.GetBytes("combined hash+sign on token");
            byte[] dest = new byte[256];

            Assert.True(ec.TrySignData(data, dest, hash, out int written));
            Assert.True(written > 0);

            var sig = dest.AsSpan(0, written);
            Assert.True(ec.VerifyData(data.AsSpan(), sig, hash));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(ec.VerifyData(tampered.AsSpan(), sig, hash));
        });

    // SHA-224 ECDSA signing maps to CKM_ECDSA_SHA224, gated like SHA-1 (no BCL HashAlgorithmName
    // constant, no benefit over SHA-256), so it requires the AllowInsecure policy. Uses the span TrySignData /
    // VerifyData(ReadOnlySpan, …) overloads deliberately: the byte[] SignData(HashAlgorithmName) /
    // VerifyData(byte[],...) convenience overloads do NOT reach ECDsaPkcs11's own overrides at all —
    // confirmed empirically (not assumed): the BCL's ECDsa base class pre-hashes via the protected
    // HashData hook, which throws CryptographicException("'SHA224' is not a known hash algorithm")
    // before this class's code ever runs, on every backend. See the class remarks on ECDsaPkcs11.
    internal static void Assert_TrySignData_Sha224_UnderAllowInsecure_RoundTrips(IPkcs11Backend backend, string curve)
    {
        backend.RequireMechanisms(CKM.CKM_ECDSA_SHA224);
        WithEcDsa(backend, curve, (session, ec) =>
        {
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            {
                var hash = new HashAlgorithmName("SHA224");
                byte[] data = Encoding.UTF8.GetBytes("sha224 combined hash+sign on token");
                byte[] dest = new byte[256];

                Assert.True(ec.TrySignData(data, dest, hash, out int written));
                Assert.True(written > 0);

                var sig = dest.AsSpan(0, written);
                Assert.True(ec.VerifyData(data.AsSpan(), sig, hash));

                byte[] tampered = [.. data];
                tampered[0] ^= 0xFF;
                Assert.False(ec.VerifyData(tampered.AsSpan(), sig, hash));
            }
        });
    }

    // Requires CKM_ECDSA_SHA224 for the same reason the round-trip case above does: SignDataInternal
    // checks _key.SupportsMechanism first and only reaches the combined-mechanism path guarded by the
    // session's crypto policy check when the token advertises it. Without that check here, a build that doesn't advertise it
    // (confirmed in CI: SoftHSM 2.5 / PKCS11 v2.40 does not, unlike the SoftHSM2 build used elsewhere in
    // this suite) takes the managed HashData fallback instead, which throws NotSupportedException, not
    // CryptoPolicyViolationException — a real failure this exact gap caused, not a hypothetical one.
    internal static void Assert_TrySignData_Sha224_WithoutAllowInsecure_Throws(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_ECDSA_SHA224);
        WithEcDsa(backend, "P-256", (_, ec) =>
            Assert.Throws<CryptoPolicyViolationException>(() =>
                ec.TrySignData(Encoding.UTF8.GetBytes("x"), new byte[256], new HashAlgorithmName("SHA224"), out int _)));
    }

    internal static void Assert_TrySignData_DestinationTooSmall_ReturnsFalse(IPkcs11Backend backend) =>
        WithEcDsa(backend, "P-256", (ec, hash) =>
        {
            byte[] data = Encoding.UTF8.GetBytes("too small destination");
            Assert.False(ec.TrySignData(data, new byte[1], hash, out int written));
            Assert.Equal(0, written);
        });

    internal static void Assert_SignHash_VerifyHash_RoundTrips(IPkcs11Backend backend) =>
        WithEcDsa(backend, "P-256", (ec, _) =>
        {
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes("raw ecdsa over a digest"));
            byte[] sig = ec.SignHash(hash);
            Assert.True(ec.VerifyHash(hash, sig));

            hash[0] ^= 0xFF;
            Assert.False(ec.VerifyHash(hash, sig));
        });

    internal static void Assert_SignHash_NullHash_Throws(IPkcs11Backend backend) =>
        WithEcDsa(backend, "P-256", (ec, _) =>
            Assert.Throws<ArgumentNullException>(() => ec.SignHash(null!)));

    internal static void Assert_VerifyHash_NullArguments_Throw(IPkcs11Backend backend) =>
        WithEcDsa(backend, "P-256", (ec, _) =>
        {
            Assert.Throws<ArgumentNullException>(() => ec.VerifyHash(null!, new byte[64]));
            Assert.Throws<ArgumentNullException>(() => ec.VerifyHash(new byte[32], null!));
        });

    internal static void Assert_ExportParameters_PublicOnly_FromPublicHandle_ReturnsPoint(IPkcs11Backend backend, string curve)
    {
        var (_, _, expectedOidValue) = Spec(curve);
        WithEcDsa(backend, curve, (ec, _) =>
        {
            var p = ec.ExportParameters(includePrivateParameters: false);
            Assert.Equal(expectedOidValue, p.Curve.Oid.Value);
            Assert.NotNull(p.Q.X);
            Assert.NotNull(p.Q.Y);
            Assert.Null(p.D); // private parts must not be set
        });
    }

    // Cross-library verification: export the public key, rebuild an ECDsa from it, verify the PKCS#11
    // signature under the BCL — catches a wrong named-curve OID or mangled point. CKM_ECDSA emits raw
    // r‖s, so the BCL interprets the signature as IEEE P1363.
    internal static void Assert_SignData_VerifiesUnderBclFromExportedPublicKey(IPkcs11Backend backend, string curve) =>
        WithEcDsa(backend, curve, (ec, hash) =>
        {
            byte[] data = Encoding.UTF8.GetBytes("cross-library verify");
            byte[] sig = ec.SignData(data, hash);

            using var bcl = ECDsa.Create(ec.ExportParameters(includePrivateParameters: false));
            Assert.True(bcl.VerifyData(data, sig, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        });

    internal static void Assert_ExportParameters_Private_ThrowsInsecure(IPkcs11Backend backend) =>
        WithEcDsa(backend, "P-256", (ec, _) =>
            Assert.Throws<CryptoPolicyViolationException>(() => ec.ExportParameters(includePrivateParameters: true)));

    internal static void Assert_ExportExplicitParameters_Throws(IPkcs11Backend backend) =>
        WithEcDsa(backend, "P-256", (ec, _) =>
            Assert.Throws<NotSupportedException>(() => ec.ExportExplicitParameters(includePrivateParameters: false)));

    internal static void Assert_ImportParameters_Throws(IPkcs11Backend backend) =>
        WithEcDsa(backend, "P-256", (ec, _) =>
            Assert.Throws<NotSupportedException>(() => ec.ImportParameters(default)));

    internal static void Assert_GenerateKey_Throws(IPkcs11Backend backend) =>
        WithEcDsa(backend, "P-256", (ec, _) =>
            Assert.Throws<NotSupportedException>(() => ec.GenerateKey(BclECCurve.NamedCurves.nistP256)));

    // === Curves whose group order is one bit longer than the field ===========================
    // On secp160r1 and secp224k1, n is just above 2^160 and 2^224, so r and s can take one byte more than a
    // coordinate. A DER signature is converted to r‖s sized from n for the token, not from KeySize (the
    // field size, as the BCL reports it). Valid signatures from the Wycheproof test vectors (C2SP/wycheproof),
    // ecdsa_secp224k1_sha256_test.json and ecdsa_secp160r1_sha256_test.json, each with its own public key.

    private sealed record WycheproofVector(string Curve, string Wx, string Wy, string Msg, string Sig);

    private static readonly Dictionary<string, WycheproofVector> OrderVectors = new(StringComparer.Ordinal)
    {
        // tcId 352, "k*G has a large x-coordinate": s is 29 bytes.
        ["secp224k1/352"] = new("secp224k1",
            "2cad534f3a9b9f7af75ef6b52b34e98b39afca1f76cdb3a3478d5e04",
            "05f4b39f0b8e0e89e4d21c43d7046501cbc5506344f717487860c76a",
            "313233343030",
            "303e021d00fffffffffffffffffffffffffffffffffffffffffffffffeffffe56c021d010000000000000000000000000001dce8d2ec6184caf0a971769fb1f4"),
        // tcId 1, "valid pseudorandom signature": r is 28 bytes, s 28 bytes with its sign-padding zero.
        ["secp224k1/1"] = new("secp224k1",
            "2ef983fa542b64472e2bc405d9eedd861acc9a7f814fad8275ce6b9a",
            "3459ba4ab52164883bd29eb6ac7e6d22ac7d302c053dc39684928ef9",
            "",
            "303d021c464bb0fb437b06922073e124528486e500b1394a05e86b0bf58aa70b021d00f2819cdd8f311adae3930586d1fb883ae071cc8d60435904ffb9d872"),
        // tcId 351, "k*G has a large x-coordinate": s is 21 bytes.
        ["secp160r1/351"] = new("secp160r1",
            "9452cac89fd846036b3f4ddf995da4bc958e1911",
            "5f8b30d6cca6988ab496ff2f17e24f08faac75b7",
            "313233343030",
            "302e021500ffffffffffffffffffffffffffffffff7ffffffc02150100000000000000000001f4c8f927aed3ca752254"),
        // tcId 1, "valid pseudorandom signature".
        ["secp160r1/1"] = new("secp160r1",
            "b0046a56f874d30ea2ba7ac1a935fd9d754ee641",
            "7b9a54d275806819ec30b15618f5625115241f46",
            "",
            "302c021449c9656cd8cbee4456548d63a7fc480791909c4202146ff78980793ee086a2e66e01a490bdfc03f2d302"),
        // tcId 168, "Signature with special case values r=0 and s=0": invalid.
        ["secp160r1/168"] = new("secp160r1",
            "50cd6584a80522992ecc20c20280c358c15e5085",
            "e0a12cbbb20fbec12ce194c0f90b72331db90fce",
            "313233343030",
            "3006020100020100"),
    };

    // r and s each take the group order's byte length in the token's r‖s form.
    private static int SignatureFieldSize(string curve)
    {
        Assert.True(Pkcs11CurveCatalog.Default.TryGetByName(curve, out Pkcs11CurveInfo? info));
        return (info.OrderSizeBits + 7) / 8;
    }

    // Imports the vector's public key and runs the body on it. The curves are below the default policy's
    // floor, so the body runs under AllowInsecure. Tokens don't agree on the error for a curve they don't
    // implement, so these cases are wired only into the backends that take secp160r1 and secp224k1.
    private static void WithVectorKey(IPkcs11Backend backend, WycheproofVector v, Action<ECDsaPkcs11> body)
    {
        backend.RequireMechanism(CKM.CKM_ECDSA);
        Assert.True(Pkcs11CurveCatalog.Default.TryGetByName(v.Curve, out Pkcs11CurveInfo? info));
        using var session = OpenSession(backend);
        using IDisposable insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        using var template = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .EcParams(info.ToCurve().GetEcParams())
            .Attribute(CKA.CKA_EC_POINT, TestKeys.DerEcPoint(Convert.FromHexString(v.Wx), Convert.FromHexString(v.Wy)))
            .Verify()
            .OnToken(false)
            .Build();
        using var key = session.ImportKey(template);
        using var ec = new ECDsaPkcs11(key);
        body(ec);
    }

    internal static void Assert_VerifyHash_DerSignature_OrderLongerThanField_Verifies(IPkcs11Backend backend, string vector)
    {
        WycheproofVector v = OrderVectors[vector];
        WithVectorKey(backend, v, ec =>
        {
            byte[] msg = Convert.FromHexString(v.Msg);
            byte[] der = Convert.FromHexString(v.Sig);
            byte[] hash = SHA256.HashData(msg);

            Assert.True(ec.VerifyHash(hash, der, DSASignatureFormat.Rfc3279DerSequence));
            Assert.True(ec.VerifyData(msg, der, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));

            // The same signature in the token's r‖s form, r and s each as long as the order.
            byte[] ieee = DssSignatureEncoding.DerToIeeeP1363(der, SignatureFieldSize(v.Curve))!;
            Assert.True(ec.VerifyHash(hash, ieee));
            Assert.True(ec.VerifyHash(hash, ieee, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

            byte[] tampered = [.. der];
            tampered[^1] ^= 0x01;
            Assert.False(ec.VerifyHash(hash, tampered, DSASignatureFormat.Rfc3279DerSequence));
        });
    }

    internal static void Assert_VerifyHash_DerZeroSignature_ReturnsFalse(IPkcs11Backend backend)
    {
        WycheproofVector v = OrderVectors["secp160r1/168"];
        WithVectorKey(backend, v, ec =>
        {
            byte[] msg = Convert.FromHexString(v.Msg);
            byte[] der = Convert.FromHexString(v.Sig);

            Assert.False(ec.VerifyHash(SHA256.HashData(msg), der, DSASignatureFormat.Rfc3279DerSequence));
            Assert.False(ec.VerifyData(msg, der, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
        });
    }

    // A key generated on the curve: the token's r‖s takes the order's length for r and s, and a DER
    // signature made from it verifies, under the BCL too.
    internal static void Assert_SignHash_OrderLongerThanField_RoundTrips(IPkcs11Backend backend, string curve)
    {
        backend.RequireMechanisms(CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA);
        Assert.True(Pkcs11CurveCatalog.Default.TryGetByName(curve, out Pkcs11CurveInfo? info));
        using var session = OpenSession(backend);
        using IDisposable insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        using var key = GenerateEcKey(session, info.ToCurve().GetEcParams());
        try
        {
            using var ec = new ECDsaPkcs11(key);
            Assert.Equal(info.FieldSizeBits, ec.KeySize);
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes($"ecdsa on {curve}"));

            Assert.Equal(2 * SignatureFieldSize(curve), ec.SignHash(hash).Length);

            byte[] der = ec.SignHash(hash, DSASignatureFormat.Rfc3279DerSequence);
            Assert.True(ec.VerifyHash(hash, der, DSASignatureFormat.Rfc3279DerSequence));

            byte[] data = Encoding.UTF8.GetBytes("signed data");
            byte[] derData = ec.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            Assert.True(ec.VerifyData(data, derData, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));

            using var bcl = ECDsa.Create(ec.ExportParameters(includePrivateParameters: false));
            Assert.True(bcl.VerifyHash(hash, der, DSASignatureFormat.Rfc3279DerSequence));
        }
        finally
        {
            try { key.Destroy(); } catch { /* best-effort cleanup */ }
        }
    }
}
