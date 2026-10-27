using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

// MLKem (FIPS 203) is an evaluation-only BCL API (SYSLIB5006); suppress here.
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// MLKemPkcs11 over the in-process <c>ManagedSoftToken</c> (a BCL-backed PKCS#11 fake). The vendored
/// SoftHSM is not built WITH_ML_KEM, so the SoftHsm KAT skips; the managed token generates the key pair
/// and runs <c>C_EncapsulateKey</c>/<c>C_DecapsulateKey</c>, with both sides recovering the same shared
/// secret. Reading the shared secret is the extract-and-destroy path, gated by the secure-defaults policy
/// (via <c>UsePolicy(CryptoPolicy.AllowInsecure)</c>). The real crypto is cross-checked against the BCL
/// <see cref="MLKem"/> primitive
/// (FIPS 203). Crypto cases are gated on <see cref="MLKem.IsSupported"/>; argument/ctor cases that throw
/// before any native call stay <c>[Fact]</c>.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class MLKemPkcs11Tests_Managed
{
    private static MLKemAlgorithm BclAlgorithm(CkpMlKem p) => p switch
    {
        CkpMlKem.CKP_ML_KEM_512 => MLKemAlgorithm.MLKem512,
        CkpMlKem.CKP_ML_KEM_768 => MLKemAlgorithm.MLKem768,
        CkpMlKem.CKP_ML_KEM_1024 => MLKemAlgorithm.MLKem1024,
        _ => throw new ArgumentOutOfRangeException(nameof(p)),
    };

    // Generates an ML-KEM key pair for the given parameter set on the managed token, wraps it as an
    // MLKemPkcs11, runs the body, then cleans up the key.
    private static void WithMlKem(CkpMlKem parameterSet, bool allowInsecure, Action<Pkcs11Session, MLKemPkcs11> body)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using IDisposable? insecure = allowInsecure ? session.UsePolicy(CryptoPolicy.AllowInsecure) : null;

        using var key = GenerateMlKem(session, parameterSet);
        try
        {
            using var mlkem = new MLKemPkcs11(key);
            body(session, mlkem);
        }
        finally
        {
            try { key.Destroy(); }
            catch { /* best-effort cleanup */ }
        }
    }

    private static Pkcs11Key GenerateMlKem(Pkcs11Session session, CkpMlKem parameterSet)
    {
        string label = $"mlkem-{Guid.NewGuid():N}";
        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM)
            .Label(label)
            .Attribute(CKA.CKA_ENCAPSULATE, true)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)parameterSet).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM)
            .Label(label)
            .Attribute(CKA.CKA_DECAPSULATE, true).Build();

        return session.GenerateKeyPair(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), pubTpl, privTpl);
    }

    // A ciphertext for the key, made off the token so that producing it extracts nothing.
    private static byte[] BclCiphertextFor(MLKemPkcs11 mlkem)
    {
        using var bcl = MLKem.ImportEncapsulationKey(mlkem.Algorithm, mlkem.ExportEncapsulationKey());
        bcl.Encapsulate(out byte[] ciphertext, out _);
        return ciphertext;
    }

    private static int SecretKeyCount(Pkcs11Session session)
    {
        using var filter = ObjectTemplate.Empty().Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_SECRET_KEY).Build();
        using var keys = session.FindKeys(filter);
        return keys.Count;
    }

    public static TheoryData<CkpMlKem> ParameterSets =>
    [
        CkpMlKem.CKP_ML_KEM_512,
        CkpMlKem.CKP_ML_KEM_768,
        CkpMlKem.CKP_ML_KEM_1024,
    ];

    // === Encapsulate / decapsulate round-trips ============================

    [Theory(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    [MemberData(nameof(ParameterSets))]
    public void EncapsulateDecapsulate_RoundTrips(CkpMlKem parameterSet) =>
        WithMlKem(parameterSet, allowInsecure: true, (ws, mlkem) =>
    {
        Assert.Equal(BclAlgorithm(parameterSet), mlkem.Algorithm);

        mlkem.Encapsulate(out byte[] ciphertext, out byte[] sharedSecretEnc);
        Assert.Equal(mlkem.Algorithm.CiphertextSizeInBytes, ciphertext.Length);
        Assert.Equal(mlkem.Algorithm.SharedSecretSizeInBytes, sharedSecretEnc.Length);

        byte[] sharedSecretDec = mlkem.Decapsulate(ciphertext);
        Assert.Equal(sharedSecretEnc, sharedSecretDec);
    });

    // BCL cross-check: export the encapsulation key from the token, import it into a BCL MLKem,
    // encapsulate off-token, then decapsulate the resulting ciphertext on the token. The shared secrets
    // must match — the token holds the matching decapsulation key.
    [Theory(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    [MemberData(nameof(ParameterSets))]
    public void Decapsulate_BclEncapsulation_MatchesSharedSecret(CkpMlKem parameterSet) =>
        WithMlKem(parameterSet, allowInsecure: true, (ws, mlkem) =>
    {
        byte[] ek = mlkem.ExportEncapsulationKey();

        using var bcl = MLKem.ImportEncapsulationKey(BclAlgorithm(parameterSet), ek);
        bcl.Encapsulate(out byte[] ciphertext, out byte[] bclSharedSecret);

        byte[] tokenSharedSecret = mlkem.Decapsulate(ciphertext);
        Assert.Equal(bclSharedSecret, tokenSharedSecret);
    });

    // Two encapsulations to the same key produce distinct ciphertexts and distinct shared secrets,
    // yet each round-trips correctly.
    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void Encapsulate_TwiceProducesDistinctCiphertexts() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: true, (ws, mlkem) =>
    {
        mlkem.Encapsulate(out byte[] ct1, out byte[] ss1);
        mlkem.Encapsulate(out byte[] ct2, out byte[] ss2);

        Assert.NotEqual(ct1, ct2);
        Assert.NotEqual(ss1, ss2);
        Assert.Equal(ss1, mlkem.Decapsulate(ct1));
        Assert.Equal(ss2, mlkem.Decapsulate(ct2));
    });

    // === Secure-defaults gating ===========================================

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void Encapsulate_GatedByDefault_Throws() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: false, (ws, mlkem) =>
            Assert.Throws<CryptoPolicyViolationException>(() => mlkem.Encapsulate(out _, out _)));

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void Decapsulate_GatedByDefault_Throws() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: false, (ws, mlkem) =>
        {
            // Produce a valid ciphertext off-token (no extraction needed) so the gate — not a bad
            // ciphertext — is what rejects the decapsulate.
            byte[] ek = mlkem.ExportEncapsulationKey();
            using var bcl = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, ek);
            bcl.Encapsulate(out byte[] ciphertext, out _);

            Assert.Throws<CryptoPolicyViolationException>(() => mlkem.Decapsulate(ciphertext));
        });

    // UsePolicy(CryptoPolicy.AllowInsecure) opts in only for its lifetime; outside it the gate re-engages.
    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void Encapsulate_UsePolicyAllowInsecure_OptsInThenReengages() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: false, (session, mlkem) =>
        {
            using (session.UsePolicy(CryptoPolicy.AllowInsecure))
                mlkem.Encapsulate(out _, out _); // must not throw inside the scope

            Assert.Throws<CryptoPolicyViolationException>(() => mlkem.Encapsulate(out _, out _));
        });

    // Refuses reading key material off the token and allows everything else.
    private sealed class NoExportPolicy : ICryptoPolicy
    {
        public List<PolicyRequest> Seen { get; } = [];
        public string Name => "NoExport";
        public bool AllowsOverride => false;
        public PolicyDecision Evaluate(PolicyRequest request)
        {
            Seen.Add(request);
            return request is KeyMaterialExportRequest ? PolicyDecision.Deny("no export") : PolicyDecision.Allow;
        }
    }

    // The default policy also refuses the extractable shared-secret template, which would hide a missing
    // export check. A policy that accepts the template but refuses plaintext secrets must still stop both
    // operations, before the token creates the secret.
    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void SharedSecretExport_IsCheckedOnItsOwn_BeforeTheToken()
    {
        var policy = new NoExportPolicy();
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library, policy);
        using var key = GenerateMlKem(session, CkpMlKem.CKP_ML_KEM_768);
        using var mlkem = new MLKemPkcs11(key);
        byte[] ciphertext = BclCiphertextFor(mlkem);
        policy.Seen.Clear();

        var encapsulate = Assert.Throws<CryptoPolicyViolationException>(() => mlkem.Encapsulate(out _, out _));
        var decapsulate = Assert.Throws<CryptoPolicyViolationException>(() => mlkem.Decapsulate(ciphertext));

        Assert.Equal(KeyMaterialExportKind.KemSharedSecret, Assert.IsType<KeyMaterialExportRequest>(encapsulate.Request).Kind);
        Assert.Equal(KeyMaterialExportKind.KemSharedSecret, Assert.IsType<KeyMaterialExportRequest>(decapsulate.Request).Kind);
        Assert.Empty(policy.Seen.OfType<KeyTemplateRequest>());
        Assert.Equal(0, SecretKeyCount(session));
    }

    // The shared secret is created on the token as an extractable object only so its value can be read;
    // once read it must not stay there.
    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void EncapsulateAndDecapsulate_LeaveNoSharedSecretOnTheToken() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: true, (session, mlkem) =>
        {
            byte[] ciphertext = BclCiphertextFor(mlkem);

            mlkem.Encapsulate(out _, out _);
            Assert.Equal(0, SecretKeyCount(session));

            mlkem.Decapsulate(ciphertext);
            Assert.Equal(0, SecretKeyCount(session));
        });

    // === Extract-and-destroy cleanup failures =============================

    // The extract-and-destroy path creates a transient, extractable shared-secret object on the
    // token, reads its bytes, then destroys it. If C_DestroyObject fails, that extractable copy
    // lingers on-token — the adapter must surface the failure (not swallow it) and must not hand
    // back a shared secret alongside a failed cleanup.
    [Theory(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    [InlineData(true)]
    [InlineData(false)]
    public void WhenDestroyFails_SurfacesPkcs11Exception_AndHandsBackNoSecret(bool encapsulate)
    {
        var token = new ManagedSoftToken();
        using var library = token.Load();
        using var session = ManagedToken.OpenSession(library);
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);

        using var key = GenerateMlKem(session, CkpMlKem.CKP_ML_KEM_768);
        try
        {
            using var mlkem = new MLKemPkcs11(key);
            byte[] ciphertext = new byte[mlkem.Algorithm.CiphertextSizeInBytes];
            byte[] sharedSecret = new byte[mlkem.Algorithm.SharedSecretSizeInBytes];
            if (!encapsulate)
                ciphertext = BclCiphertextFor(mlkem);

            // Make every C_DestroyObject report failure so the shared-secret object cannot be removed.
            token.DestroyObjectResultOverride = CKR.CKR_FUNCTION_FAILED;

            var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
            {
                if (encapsulate)
                    mlkem.Encapsulate(ciphertext, sharedSecret);
                else
                    mlkem.Decapsulate(ciphertext, sharedSecret);
            });
            Assert.Equal(CKR.CKR_FUNCTION_FAILED, ex.ReturnValue);
            Assert.Contains("may remain on-token", ex.Message, StringComparison.Ordinal);
            Assert.All(sharedSecret, b => Assert.Equal(0, b));
        }
        finally
        {
            // Lift the override so the key can actually be cleaned up.
            token.DestroyObjectResultOverride = null;
            try { key.Destroy(); }
            catch { /* best-effort cleanup */ }
        }
    }

    // === A token that misbehaves =========================================

    // Opens a session over the given managed token under AllowInsecure, generates an ML-KEM-768 key
    // pair, and runs the body with a ciphertext for the key made off the token.
    private static void WithMisbehavingToken(ManagedSoftToken token, Action<Pkcs11Session, MLKemPkcs11, byte[]> body)
    {
        using var library = token.Load();
        using var session = ManagedToken.OpenSession(library);
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        using var key = GenerateMlKem(session, CkpMlKem.CKP_ML_KEM_768);
        using var mlkem = new MLKemPkcs11(key);
        body(session, mlkem, BclCiphertextFor(mlkem));
    }

    // A filled buffer, so a test can tell that a failure zeroed it.
    private static byte[] Filled(int length) => [.. Enumerable.Repeat((byte)0xA5, length)];

    // SoftHSM refuses CKA_VALUE_LEN on the decapsulated secret's template. The first decapsulation
    // retries without it and records that on the library; the next one goes straight to that form.
    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void Decapsulate_TokenRefusesValueLen_RetriesWithoutIt_AndRemembers() =>
        WithMisbehavingToken(new ManagedSoftToken { DecapsulateRejectsValueLen = true }, (session, mlkem, _) =>
        {
            mlkem.Encapsulate(out byte[] ciphertext, out byte[] sharedSecret);
            Assert.Null(session.Library.MlKemDecapsulateOmitsValueLen);

            Assert.Equal(sharedSecret, mlkem.Decapsulate(ciphertext));
            Assert.True(session.Library.MlKemDecapsulateOmitsValueLen);

            Assert.Equal(sharedSecret, mlkem.Decapsulate(ciphertext));
            Assert.True(session.Library.MlKemDecapsulateOmitsValueLen);
        });

    [Theory(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    [InlineData(true)]
    [InlineData(false)]
    public void SharedSecretUnreadable_ThrowsPkcs11Exception_AndHandsBackNoSecret(bool encapsulate) =>
        WithMisbehavingToken(new ManagedSoftToken { KemWithholdsSharedSecret = true }, (session, mlkem, ciphertext) =>
        {
            byte[] sharedSecret = Filled(mlkem.Algorithm.SharedSecretSizeInBytes);

            var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
            {
                if (encapsulate)
                    mlkem.Encapsulate(new byte[mlkem.Algorithm.CiphertextSizeInBytes], sharedSecret);
                else
                    mlkem.Decapsulate(ciphertext, sharedSecret);
            });
            Assert.Equal(CKR.CKR_ATTRIBUTE_SENSITIVE, ex.ReturnValue);
            Assert.Contains("unreadable", ex.Message, StringComparison.Ordinal);
            Assert.All(sharedSecret, b => Assert.Equal(0, b));
            Assert.Equal(0, SecretKeyCount(session));
        });

    // A shared secret shorter or longer than the parameter set's 32 bytes is refused, never copied in part.
    [Theory(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    [InlineData(true, -1)]
    [InlineData(true, 1)]
    [InlineData(false, -1)]
    [InlineData(false, 1)]
    public void SharedSecretOfTheWrongLength_ThrowsPkcs11Exception_AndHandsBackNoSecret(bool encapsulate, int lengthDelta)
    {
        var token = new ManagedSoftToken
        {
            KemSharedSecretOverride = ss => lengthDelta < 0 ? ss[..^1] : [.. ss, 0x00],
        };
        WithMisbehavingToken(token, (session, mlkem, ciphertext) =>
        {
            byte[] sharedSecret = Filled(mlkem.Algorithm.SharedSecretSizeInBytes);

            var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
            {
                if (encapsulate)
                    mlkem.Encapsulate(new byte[mlkem.Algorithm.CiphertextSizeInBytes], sharedSecret);
                else
                    mlkem.Decapsulate(ciphertext, sharedSecret);
            });
            Assert.Equal(CKR.CKR_GENERAL_ERROR, ex.ReturnValue);
            Assert.Contains($"{32 + lengthDelta}-byte shared secret", ex.Message, StringComparison.Ordinal);
            Assert.All(sharedSecret, b => Assert.Equal(0, b));
            Assert.Equal(0, SecretKeyCount(session));
        });
    }

    // A short ciphertext is the token's fault. The secret was already copied out when the ciphertext is
    // checked, so the failure must zero it again.
    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void Encapsulate_TokenCiphertextTooShort_ThrowsPkcs11Exception_AndHandsBackNoSecret() =>
        WithMisbehavingToken(new ManagedSoftToken { KemCiphertextOverride = ct => ct[..^1] }, (session, mlkem, _) =>
        {
            int expected = mlkem.Algorithm.CiphertextSizeInBytes;
            byte[] ciphertext = new byte[expected];
            byte[] sharedSecret = Filled(mlkem.Algorithm.SharedSecretSizeInBytes);

            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => mlkem.Encapsulate(ciphertext, sharedSecret));
            Assert.Equal(CKR.CKR_GENERAL_ERROR, ex.ReturnValue);
            Assert.Contains($"{expected - 1}-byte buffer", ex.Message, StringComparison.Ordinal);
            Assert.All(sharedSecret, b => Assert.Equal(0, b));
            Assert.Equal(0, SecretKeyCount(session));
        });

    // When the token also fails to destroy the secret object, the failure that stopped the operation is
    // still the one reported: the cleanup is best-effort on that path, and the object is a session object
    // the token drops at C_CloseSession.
    [Theory(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    [InlineData(true)]
    [InlineData(false)]
    public void FailedOperation_WhenDestroyAlsoFails_ReportsTheOriginalFailure(bool encapsulate)
    {
        var token = new ManagedSoftToken { KemSharedSecretOverride = ss => ss[..^1] };
        WithMisbehavingToken(token, (_, mlkem, ciphertext) =>
        {
            byte[] sharedSecret = Filled(mlkem.Algorithm.SharedSecretSizeInBytes);
            token.DestroyObjectResultOverride = CKR.CKR_FUNCTION_FAILED;
            try
            {
                var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
                {
                    if (encapsulate)
                        mlkem.Encapsulate(new byte[mlkem.Algorithm.CiphertextSizeInBytes], sharedSecret);
                    else
                        mlkem.Decapsulate(ciphertext, sharedSecret);
                });
                Assert.Equal(CKR.CKR_GENERAL_ERROR, ex.ReturnValue);
                Assert.Contains("31-byte shared secret", ex.Message, StringComparison.Ordinal);
                Assert.All(sharedSecret, b => Assert.Equal(0, b));
            }
            finally
            {
                token.DestroyObjectResultOverride = null;
            }
        });
    }

    // === Key material export ==============================================

    [Theory(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    [MemberData(nameof(ParameterSets))]
    public void ExportEncapsulationKey_MatchesBclEncodingLength(CkpMlKem parameterSet) =>
        WithMlKem(parameterSet, allowInsecure: false, (ws, mlkem) =>
    {
        byte[] ek = mlkem.ExportEncapsulationKey();
        Assert.Equal(mlkem.Algorithm.EncapsulationKeySizeInBytes, ek.Length);

        // The exported bytes are the FIPS 203 encapsulation-key encoding: importable by the BCL.
        using var bcl = MLKem.ImportEncapsulationKey(BclAlgorithm(parameterSet), ek);
        Assert.Equal(BclAlgorithm(parameterSet), bcl.Algorithm);
    });

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void ExportDecapsulationKey_ThrowsInsecure() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: true, (ws, mlkem) =>
            // Refused even under the AllowInsecure policy: PKCS#11 keys are non-extractable by design.
            Assert.Throws<CryptoPolicyViolationException>(() => mlkem.ExportDecapsulationKey()));

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void ExportPrivateSeed_ThrowsInsecure() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: true, (ws, mlkem) =>
            Assert.Throws<CryptoPolicyViolationException>(() => mlkem.ExportPrivateSeed()));

    [Fact(SkipUnless = nameof(MLKem.IsSupported), SkipType = typeof(MLKem), Skip = "Requires " + nameof(MLKem.IsSupported))]
    public void ExportPkcs8PrivateKey_ThrowsInsecure() =>
        WithMlKem(CkpMlKem.CKP_ML_KEM_768, allowInsecure: true, (ws, mlkem) =>
            Assert.Throws<CryptoPolicyViolationException>(() => mlkem.ExportPkcs8PrivateKey()));

    // === Construction and argument validation (run before any native crypto) ==============

    [Fact]
    public void Ctor_NullKey_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new MLKemPkcs11(null!));
        Assert.Equal("key", ex.ParamName);
    }

    private static byte[] UlongAttr(ulong value) =>
        BitConverter.GetBytes(value).AsSpan(0, UnmanagedMemory.NativeULongSize).ToArray();

    // A real token can't be coaxed into hiding CKA_PARAMETER_SET or reporting one it never advertises on
    // a well-formed ML-KEM key, so a fake key drives these.
    [Theory]
    [MemberData(nameof(ParameterSets))]
    public void Ctor_ResolvesAlgorithm_ForEveryParameterSet(CkpMlKem parameterSet)
    {
        using var key = FakeKeys.Create(CKK.CKK_ML_KEM, _ => (CKR.CKR_OK, UlongAttr((ulong)parameterSet)));
        using var mlkem = new MLKemPkcs11(key);

        Assert.Equal(BclAlgorithm(parameterSet), mlkem.Algorithm);
    }

    [Fact]
    public void Ctor_ParameterSetAttributeSensitive_ThrowsArgumentException()
    {
        using var key = FakeKeys.Create(CKK.CKK_ML_KEM, _ => (CKR.CKR_ATTRIBUTE_SENSITIVE, null));

        var ex = Assert.Throws<ArgumentException>(() => new MLKemPkcs11(key));
        Assert.Equal("key", ex.ParamName);
        Assert.Contains("not readable", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Ctor_UnrecognizedParameterSet_ThrowsArgumentException()
    {
        using var key = FakeKeys.Create(CKK.CKK_ML_KEM, _ => (CKR.CKR_OK, UlongAttr(0xFFFF)));

        var ex = Assert.Throws<ArgumentException>(() => new MLKemPkcs11(key));
        Assert.Equal("key", ex.ParamName);
        Assert.Contains("Unrecognized ML-KEM parameter set 0xFFFF", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Ctor_NonMlKemKey_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label("aes").ValueLen(32).Encrypt().Decrypt().Build();
        using var key = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), tpl);

        var ex = Assert.Throws<ArgumentException>(() => new MLKemPkcs11(key));
        Assert.Equal("key", ex.ParamName);
    }
}
