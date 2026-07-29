using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Layout guards for the native struct layer. Two kinds:
/// (1) <b>field-offset pins</b> (LP64 / Unix) — size-only checks pass even when two same-width fields
///     are transposed or padding compensates, so the pointer/length interleavings are pinned by offset;
/// (2) <b>drift guards</b> (host-independent) — reflection census ensuring every <c>CK_*</c> struct is
///     marshalable, every <c>[PackedForPkcs11]</c> struct has a matching generated <c>_Windows</c>
///     sibling, no orphan siblings exist, and <c>PackedDispatch</c> covers the whole set.
/// </summary>
public sealed class NativeStructLayoutTests
{
    private static readonly Assembly ProdAssembly = typeof(UnmanagedMemory).Assembly;
    private const string NativeNs = "KerckhoffsLabs.Security.Cryptography.Pkcs11.Native";
    private const string RawNs = NativeNs + ".RawMechanismParams";

    public static bool IsUnix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    private static int Off<T>(string field) => (int)Marshal.OffsetOf<T>(field);

    private static IEnumerable<Type> CkStructs() =>
        ProdAssembly.GetTypes().Where(t =>
            t.IsValueType && !t.IsEnum &&
            (t.Namespace == NativeNs || t.Namespace == RawNs) &&
            t.Name.StartsWith("CK_", StringComparison.Ordinal) &&
            !t.Name.EndsWith("_Windows", StringComparison.Ordinal));

    // Same set as CkStructs(), but retaining the generated _Windows siblings: both halves of every
    // packed pair are marshalled by the dispatcher, so both must satisfy the managed==marshalled
    // invariant that Pkcs11Marshal.SizeOf relies on.
    private static IEnumerable<Type> CkStructsWithSiblings() =>
        ProdAssembly.GetTypes().Where(t =>
            t.IsValueType && !t.IsEnum &&
            (t.Namespace == NativeNs || t.Namespace == RawNs) &&
            t.Name.StartsWith("CK_", StringComparison.Ordinal));

    private static bool IsPacked(Type t) =>
        t.GetCustomAttributes().Any(a => a.GetType().Name == "PackedForPkcs11Attribute");

    private static string[] FieldNames(Type t) =>
        [.. t.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic).Select(f => f.Name)];

    // === #3 — field-offset pins (LP64: CK_ULONG = 8, pointer = 8, natural align) ==========

    [ConditionalFact(nameof(IsUnix))]
    public void Lp64_Offsets_GcmParams()
    {
        Assert.Equal(0, Off<CK_GCM_PARAMS>("Iv"));
        Assert.Equal(8, Off<CK_GCM_PARAMS>("IvLen"));
        Assert.Equal(16, Off<CK_GCM_PARAMS>("IvBits"));
        Assert.Equal(24, Off<CK_GCM_PARAMS>("AAD"));
        Assert.Equal(32, Off<CK_GCM_PARAMS>("AADLen"));
        Assert.Equal(40, Off<CK_GCM_PARAMS>("TagBits"));
    }

    [ConditionalFact(nameof(IsUnix))]
    public void Lp64_Offsets_Ecdh1DeriveParams()
    {
        Assert.Equal(0, Off<CK_ECDH1_DERIVE_PARAMS>("Kdf"));
        Assert.Equal(8, Off<CK_ECDH1_DERIVE_PARAMS>("SharedDataLen"));
        Assert.Equal(16, Off<CK_ECDH1_DERIVE_PARAMS>("SharedData"));
        Assert.Equal(24, Off<CK_ECDH1_DERIVE_PARAMS>("PublicDataLen"));
        Assert.Equal(32, Off<CK_ECDH1_DERIVE_PARAMS>("PublicData"));
    }

    [ConditionalFact(nameof(IsUnix))]
    public void Lp64_Offsets_OaepParams()
    {
        Assert.Equal(0, Off<CK_RSA_PKCS_OAEP_PARAMS>("HashAlg"));
        Assert.Equal(8, Off<CK_RSA_PKCS_OAEP_PARAMS>("Mgf"));
        Assert.Equal(16, Off<CK_RSA_PKCS_OAEP_PARAMS>("Source"));
        Assert.Equal(24, Off<CK_RSA_PKCS_OAEP_PARAMS>("SourceData"));
        Assert.Equal(32, Off<CK_RSA_PKCS_OAEP_PARAMS>("SourceDataLen"));
    }

    [ConditionalFact(nameof(IsUnix))]
    public void Lp64_Offsets_CcmParams()
    {
        Assert.Equal(0, Off<CK_CCM_PARAMS>("DataLen"));
        Assert.Equal(8, Off<CK_CCM_PARAMS>("Nonce"));
        Assert.Equal(16, Off<CK_CCM_PARAMS>("NonceLen"));
        Assert.Equal(24, Off<CK_CCM_PARAMS>("AAD"));
        Assert.Equal(32, Off<CK_CCM_PARAMS>("AADLen"));
        Assert.Equal(40, Off<CK_CCM_PARAMS>("MACLen"));
    }

    [ConditionalFact(nameof(IsUnix))]
    public void Lp64_Offsets_EddsaParams()
    {
        // PhFlag is a 1-byte BOOL; the following CK_ULONG re-aligns to offset 8.
        Assert.Equal(0, Off<CK_EDDSA_PARAMS>("PhFlag"));
        Assert.Equal(8, Off<CK_EDDSA_PARAMS>("ContextDataLen"));
        Assert.Equal(16, Off<CK_EDDSA_PARAMS>("ContextData"));
    }

    /// <summary>
    /// Pins every field's LP64 offset for the pointer-bearing param structs. Size pins cannot catch a
    /// transposition of two same-width fields — swapping a pointer with its length leaves the size
    /// identical but corrupts every call — so the full name:offset sequence is pinned instead.
    /// Rows are probed from the built assembly on Linux x64 and spot-checked against the vendored
    /// OASIS header. The five structs with hand-written Lp64_Offsets_* methods above are excluded.
    /// </summary>
    [ConditionalTheory(nameof(IsUnix))]
    // BEGIN PROBED offset pins — Linux x64, LP64
    [InlineData(typeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS), "Iv:0,Data:16,Length:24")]
    [InlineData(typeof(CK_ARIA_CBC_ENCRYPT_DATA_PARAMS), "Iv:0,Data:16,Length:24")]
    [InlineData(typeof(CK_ASYNC_DATA), "Version:0,Value:8,ValueLen:16,Object:24,AdditionalObject:32")]
    [InlineData(typeof(CK_ATTRIBUTE), "type:0,value:8,valueLen:16")]
    [InlineData(typeof(CK_C_INITIALIZE_ARGS), "CreateMutex:0,DestroyMutex:8,LockMutex:16,UnlockMutex:24,Flags:32,Reserved:40")]
    [InlineData(typeof(CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS), "Iv:0,Data:16,Length:24")]
    [InlineData(typeof(CK_CCM_MESSAGE_PARAMS), "DataLen:0,Nonce:8,NonceLen:16,NonceFixedBits:24,NonceGenerator:32,Mac:40,MacLen:48")]
    [InlineData(typeof(CK_CCM_WRAP_PARAMS), "DataLen:0,Nonce:8,NonceLen:16,NonceFixedBits:24,NonceGenerator:32,Aad:40,AadLen:48,MacLen:56")]
    [InlineData(typeof(CK_CHACHA20_PARAMS), "BlockCounter:0,BlockCounterBits:8,Nonce:16,NonceBits:24")]
    [InlineData(typeof(CK_CMS_SIG_PARAMS), "CertificateHandle:0,SigningMechanism:8,DigestMechanism:16,ContentType:24,RequestedAttributes:32,RequestedAttributesLen:40,RequiredAttributes:48,RequiredAttributesLen:56")]
    [InlineData(typeof(CK_DERIVED_KEY), "Template:0,AttributeCount:8,Key:16")]
    [InlineData(typeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS), "Iv:0,Data:8,Length:16")]
    [InlineData(typeof(CK_DSA_PARAMETER_GEN_PARAM), "Hash:0,Seed:8,SeedLen:16,Index:24")]
    [InlineData(typeof(CK_ECDH_AES_KEY_WRAP_PARAMS), "AESKeyBits:0,Kdf:8,SharedDataLen:16,SharedData:24")]
    [InlineData(typeof(CK_ECDH2_DERIVE_PARAMS), "Kdf:0,SharedDataLen:8,SharedData:16,PublicDataLen:24,PublicData:32,PrivateDataLen:40,PrivateData:48,PublicDataLen2:56,PublicData2:64")]
    [InlineData(typeof(CK_ECMQV_DERIVE_PARAMS), "Kdf:0,SharedDataLen:8,SharedData:16,PublicDataLen:24,PublicData:32,PrivateDataLen:40,PrivateData:48,PublicDataLen2:56,PublicData2:64,PublicKey:72")]
    [InlineData(typeof(CK_GCM_MESSAGE_PARAMS), "Iv:0,IvLen:8,IvFixedBits:16,IvGenerator:24,Tag:32,TagBits:40")]
    [InlineData(typeof(CK_GCM_WRAP_PARAMS), "Iv:0,IvLen:8,IvFixedBits:16,IvGenerator:24,Aad:32,AadLen:40,TagBits:48")]
    [InlineData(typeof(CK_GOSTR3410_DERIVE_PARAMS), "Kdf:0,PublicData:8,PublicDataLen:16,UKM:24,UKMLen:32")]
    [InlineData(typeof(CK_GOSTR3410_KEY_WRAP_PARAMS), "WrapOID:0,WrapOIDLen:8,UKM:16,UKMLen:24,Key:32")]
    [InlineData(typeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT), "HedgeVariant:0,Context:8,ContextLen:16,Hash:24")]
    [InlineData(typeof(CK_HKDF_PARAMS), "Extract:0,Expand:1,PrfHashMechanism:8,SaltType:16,Salt:24,SaltLen:32,SaltKey:40,Info:48,InfoLen:56")]
    [InlineData(typeof(CK_IKE_PRF_DERIVE_PARAMS), "PrfMechanism:0,DataAsKey:8,Rekey:9,Ni:16,NiLen:24,Nr:32,NrLen:40,NewKey:48")]
    [InlineData(typeof(CK_IKE1_EXTENDED_DERIVE_PARAMS), "PrfMechanism:0,HasKeygxy:8,Keygxy:16,ExtraData:24,ExtraDataLen:32")]
    [InlineData(typeof(CK_IKE1_PRF_DERIVE_PARAMS), "PrfMechanism:0,HasPrevKey:8,Keygxy:16,PrevKey:24,CkyI:32,CkyILen:40,CkyR:48,CkyRLen:56,KeyNumber:64")]
    [InlineData(typeof(CK_IKE2_PRF_PLUS_DERIVE_PARAMS), "PrfMechanism:0,HasSeedKey:8,SeedKey:16,SeedData:24,SeedDataLen:32")]
    [InlineData(typeof(CK_INTERFACE), "InterfaceName:0,FunctionList:8,Flags:16")]
    [InlineData(typeof(CK_KEA_DERIVE_PARAMS), "IsSender:0,RandomLen:8,RandomA:16,RandomB:24,PublicDataLen:32,PublicData:40")]
    [InlineData(typeof(CK_KEY_DERIVATION_STRING_DATA), "Data:0,Len:8")]
    [InlineData(typeof(CK_KEY_WRAP_SET_OAEP_PARAMS), "BC:0,X:8,XLen:16")]
    [InlineData(typeof(CK_KIP_PARAMS), "Mechanism:0,Key:8,Seed:16,SeedLen:24")]
    [InlineData(typeof(CK_MECHANISM), "Mechanism:0,Parameter:8,ParameterLen:16")]
    [InlineData(typeof(CK_OTP_PARAM), "Type:0,Value:8,ValueLen:16")]
    [InlineData(typeof(CK_OTP_PARAMS), "Params:0,Count:8")]
    [InlineData(typeof(CK_OTP_SIGNATURE_INFO), "Params:0,Count:8")]
    [InlineData(typeof(CK_PBE_PARAMS), "InitVector:0,Password:8,PasswordLen:16,Salt:24,SaltLen:32,Iteration:40")]
    [InlineData(typeof(CK_PKCS5_PBKD2_PARAMS), "SaltSource:0,SaltSourceData:8,SaltSourceDataLen:16,Iterations:24,Prf:32,PrfData:40,PrfDataLen:48,Password:56,PasswordLen:64")]
    [InlineData(typeof(CK_PKCS5_PBKD2_PARAMS2), "SaltSource:0,SaltSourceData:8,SaltSourceDataLen:16,Iterations:24,Prf:32,PrfData:40,PrfDataLen:48,Password:56,PasswordLen:64")]
    [InlineData(typeof(CK_PRF_DATA_PARAM), "Type:0,Value:8,ValueLen:16")]
    [InlineData(typeof(CK_RC5_CBC_PARAMS), "Wordsize:0,Rounds:8,Iv:16,IvLen:24")]
    [InlineData(typeof(CK_RSA_AES_KEY_WRAP_PARAMS), "AESKeyBits:0,OAEPParams:8")]
    [InlineData(typeof(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS), "Nonce:0,NonceLen:8,Tag:16")]
    [InlineData(typeof(CK_SALSA20_CHACHA20_POLY1305_PARAMS), "Nonce:0,NonceLen:8,AAD:16,AADLen:24")]
    [InlineData(typeof(CK_SALSA20_PARAMS), "BlockCounter:0,Nonce:8,NonceBits:16")]
    [InlineData(typeof(CK_SEED_CBC_ENCRYPT_DATA_PARAMS), "Iv:0,Data:16,Length:24")]
    [InlineData(typeof(CK_SIGN_ADDITIONAL_CONTEXT), "HedgeVariant:0,Context:8,ContextLen:16")]
    [InlineData(typeof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS), "PasswordLen:0,Password:8,PublicDataLen:16,PublicData:24,PAndGLen:32,QLen:40,RandomLen:48,RandomA:56,PrimeP:64,BaseG:72,SubprimeQ:80")]
    [InlineData(typeof(CK_SKIPJACK_RELAYX_PARAMS), "OldWrappedXLen:0,OldWrappedX:8,OldPasswordLen:16,OldPassword:24,OldPublicDataLen:32,OldPublicData:40,OldRandomLen:48,OldRandomA:56,NewPasswordLen:64,NewPassword:72,NewPublicDataLen:80,NewPublicData:88,NewRandomLen:96,NewRandomA:104")]
    [InlineData(typeof(CK_SP800_108_FEEDBACK_KDF_PARAMS), "PrfType:0,NumberOfDataParams:8,DataParams:16,IVLen:24,IV:32,AdditionalDerivedKeys:40,AdditionalDerivedKeysPtr:48")]
    [InlineData(typeof(CK_SP800_108_KDF_PARAMS), "PrfType:0,NumberOfDataParams:8,DataParams:16,AdditionalDerivedKeys:24,AdditionalDerivedKeysPtr:32")]
    [InlineData(typeof(CK_SSL3_KEY_MAT_OUT), "ClientMacSecret:0,ServerMacSecret:8,ClientKey:16,ServerKey:24,IVClient:32,IVServer:40")]
    [InlineData(typeof(CK_SSL3_KEY_MAT_PARAMS), "MacSizeInBits:0,KeySizeInBits:8,IVSizeInBits:16,IsExport:24,RandomInfo:32,ReturnedKeyMaterial:64")]
    [InlineData(typeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS), "RandomInfo:0,Version:32")]
    [InlineData(typeof(CK_SSL3_RANDOM_DATA), "ClientRandom:0,ClientRandomLen:8,ServerRandom:16,ServerRandomLen:24")]
    [InlineData(typeof(CK_TLS_KDF_PARAMS), "PrfMechanism:0,Label:8,LabelLength:16,RandomInfo:24,ContextData:56,ContextDataLength:64")]
    [InlineData(typeof(CK_TLS_PRF_PARAMS), "Seed:0,SeedLen:8,Label:16,LabelLen:24,Output:32,OutputLen:40")]
    [InlineData(typeof(CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS), "PrfHashMechanism:0,SessionHash:8,SessionHashLen:16,Version:24")]
    [InlineData(typeof(CK_TLS12_KEY_MAT_PARAMS), "MacSizeInBits:0,KeySizeInBits:8,IVSizeInBits:16,IsExport:24,RandomInfo:32,ReturnedKeyMaterial:64,PrfHashMechanism:72")]
    [InlineData(typeof(CK_TLS12_MASTER_KEY_DERIVE_PARAMS), "RandomInfo:0,Version:32,PrfHashMechanism:40")]
    [InlineData(typeof(CK_WTLS_KEY_MAT_OUT), "MacSecret:0,Key:8,IV:16")]
    [InlineData(typeof(CK_WTLS_KEY_MAT_PARAMS), "DigestMechanism:0,MacSizeInBits:8,KeySizeInBits:16,IVSizeInBits:24,SequenceNumber:32,IsExport:40,RandomInfo:48,ReturnedKeyMaterial:80")]
    [InlineData(typeof(CK_WTLS_MASTER_KEY_DERIVE_PARAMS), "DigestMechanism:0,RandomInfo:8,Version:40")]
    [InlineData(typeof(CK_WTLS_PRF_PARAMS), "DigestMechanism:0,Seed:8,SeedLen:16,Label:24,LabelLen:32,Output:40,OutputLen:48")]
    [InlineData(typeof(CK_WTLS_RANDOM_DATA), "ClientRandom:0,ClientRandomLen:8,ServerRandom:16,ServerRandomLen:24")]
    [InlineData(typeof(CK_X2RATCHET_INITIALIZE_PARAMS), "Sk:0,PeerPublicPrekey:8,PeerPublicIdentity:16,OwnPublicIdentity:24,EncryptedHeader:32,Curve:40,AeadMechanism:48,KdfMechanism:56")]
    [InlineData(typeof(CK_X2RATCHET_RESPOND_PARAMS), "Sk:0,OwnPrekey:8,InitiatorIdentity:16,OwnPublicIdentity:24,EncryptedHeader:32,Curve:40,AeadMechanism:48,KdfMechanism:56")]
    [InlineData(typeof(CK_X3DH_INITIATE_PARAMS), "Kdf:0,PeerIdentity:8,PeerPrekey:16,PrekeySignature:24,OnetimeKey:32,OwnIdentity:40,OwnEphemeral:48")]
    [InlineData(typeof(CK_X3DH_RESPOND_PARAMS), "Kdf:0,IdentityId:8,PrekeyId:16,OnetimeId:24,InitiatorIdentity:32,InitiatorEphemeral:40")]
    [InlineData(typeof(CK_X9_42_DH1_DERIVE_PARAMS), "Kdf:0,OtherInfoLen:8,OtherInfo:16,PublicDataLen:24,PublicData:32")]
    [InlineData(typeof(CK_X9_42_DH2_DERIVE_PARAMS), "Kdf:0,OtherInfoLen:8,OtherInfo:16,PublicDataLen:24,PublicData:32,PrivateDataLen:40,PrivateData:48,PublicDataLen2:56,PublicData2:64")]
    [InlineData(typeof(CK_X9_42_MQV_DERIVE_PARAMS), "Kdf:0,OtherInfoLen:8,OtherInfo:16,PublicDataLen:24,PublicData:32,PrivateDataLen:40,PrivateData:48,PublicDataLen2:56,PublicData2:64,PublicKey:72")]
    // END PROBED offset pins
    public void Lp64_FieldOffsets(Type t, string expected)
    {
        var actual = string.Join(",", t
            .GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .Select(f => $"{f.Name}:{(int)Marshal.OffsetOf(t, f.Name)}"));

        Assert.Equal(expected, actual);
    }

    // === #2 — census / drift guards (host-independent) ====================================

    [Fact]
    public void EveryCkStruct_IsMarshalable()
    {
        var failures = new List<string>();
        foreach (var t in CkStructs())
        {
            try
            {
                if (Marshal.SizeOf(t) <= 0)
                    failures.Add($"{t.Name}: size <= 0");
            }
            catch (Exception ex)
            {
                failures.Add($"{t.Name}: {ex.GetType().Name}");
            }
        }

        Assert.True(failures.Count == 0, "Non-marshalable CK_* structs: " + string.Join(", ", failures));
    }

    /// <summary>
    /// Every native struct must have an identical managed and marshalled layout.
    /// <c>Pkcs11Marshal.SizeOf</c> sizes buffers with <c>Unsafe.SizeOf</c> (the managed layout) while
    /// <c>Marshal.StructureToPtr</c> fills them using the marshalled layout, so any divergence
    /// under-allocates a buffer the token then writes into. A managed <c>byte[]</c> field with
    /// <c>[MarshalAs(ByValArray)]</c> is the way this breaks: managed stores a reference where
    /// unmanaged stores the array inline. Use an <c>[InlineArray]</c> buffer instead.
    /// This is a relative assertion, so it runs on every platform leg including 32-bit Windows,
    /// where the absolute size pins are all skipped.
    /// </summary>
    [Fact]
    public void EveryCkStruct_ManagedSizeMatchesMarshalledSize()
    {
        var unsafeSizeOf = typeof(Unsafe).GetMethods()
            .Single(m => m.Name == nameof(Unsafe.SizeOf)
                      && m.IsGenericMethodDefinition
                      && m.GetParameters().Length == 0);

        var failures = new List<string>();
        foreach (var t in CkStructsWithSiblings())
        {
            int marshalled = Marshal.SizeOf(t);
            int managed = (int)unsafeSizeOf.MakeGenericMethod(t).Invoke(null, null)!;
            if (marshalled != managed)
                failures.Add($"{t.Name}: marshalled={marshalled} managed={managed}");
        }

        Assert.True(failures.Count == 0,
            "Managed layout must equal marshalled layout for every native struct. Divergent: "
            + string.Join("; ", failures));
    }

    [Fact]
    public void EveryPackedStruct_HasWindowsSiblingWithMatchingFields()
    {
        var packed = CkStructs().Where(IsPacked).ToList();
        Assert.NotEmpty(packed); // sanity: the reflection filter actually finds the packed set

        var failures = new List<string>();
        foreach (var t in packed)
        {
            var sibling = ProdAssembly.GetType(t.FullName + "_Windows");
            if (sibling is null)
            {
                failures.Add($"{t.Name}: no _Windows sibling generated");
                continue;
            }

            var unified = FieldNames(t).ToHashSet();
            var win = FieldNames(sibling).ToHashSet();
            if (!unified.SetEquals(win))
            {
                string missing = string.Join(",", unified.Except(win));
                string extra = string.Join(",", win.Except(unified));
                failures.Add($"{t.Name}: field mismatch (sibling missing [{missing}], extra [{extra}])");
            }
        }

        Assert.True(failures.Count == 0, string.Join("; ", failures));
    }

    [Fact]
    public void NoOrphan_WindowsSiblings()
    {
        var siblings = ProdAssembly.GetTypes().Where(t =>
            t.IsValueType &&
            (t.Namespace == NativeNs || t.Namespace == RawNs) &&
            t.Name.EndsWith("_Windows", StringComparison.Ordinal)).ToList();

        // Exactly one sibling per [PackedForPkcs11] struct, and every sibling traces back to one.
        Assert.Equal(CkStructs().Count(IsPacked), siblings.Count);

        foreach (var s in siblings)
        {
            string originName = s.FullName![..^"_Windows".Length];
            var origin = ProdAssembly.GetType(originName);
            Assert.True(origin is not null && IsPacked(origin), $"orphan sibling {s.Name} (no [PackedForPkcs11] origin)");
        }
    }

    [Fact]
    public void PackedDispatch_SizeOfWindows_CoversEveryPackedStruct()
    {
        var method = typeof(PackedDispatch).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Single(m => m.Name == "SizeOfWindows" && m.IsGenericMethodDefinition && m.GetParameters().Length == 0);

        var failures = new List<string>();
        foreach (var t in CkStructs().Where(IsPacked))
        {
            try
            {
                int dispatched = (int)method.MakeGenericMethod(t).Invoke(null, null)!;
                int expected = Marshal.SizeOf(ProdAssembly.GetType(t.FullName + "_Windows")!);
                if (dispatched != expected)
                    failures.Add($"{t.Name}: dispatch {dispatched} != sibling {expected}");
            }
            catch (Exception ex)
            {
                failures.Add($"{t.Name}: {ex.InnerException?.GetType().Name ?? ex.GetType().Name}");
            }
        }

        Assert.True(failures.Count == 0, string.Join("; ", failures));
    }
}
