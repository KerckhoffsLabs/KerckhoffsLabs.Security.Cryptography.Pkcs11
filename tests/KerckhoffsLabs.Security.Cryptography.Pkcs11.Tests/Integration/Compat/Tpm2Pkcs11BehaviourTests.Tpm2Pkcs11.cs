using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// CKM_AES_CFB128 is the one AES mode every TPM here has: these cases end its operations, not use it.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Compat;

/// <summary>
/// What tpm2-pkcs11 does that the shared cases don't reach: the v3.0 NULL-mechanism cancel and interface
/// lookup, C_CloseAllSessions, the ECDH peer point forms, CKM_ECDSA digests of any length, the key-pair
/// rollback after a refused template, and the refusals of templates and keys it can't honour. Each case
/// pins the return code PKCS#11 (or the token's documented limit) calls for.
/// </summary>
[Collection("Tpm2Pkcs11")]
public sealed unsafe class Tpm2Pkcs11BehaviourTests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    private const string Available = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available);

    // ===== Helpers ==========================================================================================

    /// <summary>The return code <paramref name="call"/> throws with, or CKR_OK.</summary>
    private static CKR Rv(Action call)
    {
        try
        {
            call();
            return CKR.CKR_OK;
        }
        catch (Pkcs11Exception e)
        {
            return e.ReturnValue;
        }
    }

    private Pkcs11SessionCore OpenSession() => TestKeys.OpenLoggedInSession(_backend);

    private void Close(Pkcs11SessionCore session)
    {
        TestKeys.LogoutIfRequired(_backend, session);
        session.Dispose();
    }

    /// <summary>tpm2-pkcs11's own export <paramref name="name"/>, which the wrapper can't call as the case needs.</summary>
    private IntPtr Export(string name)
    {
        IntPtr library = NativeLibrary.Load(_backend.LibraryPath);
        try
        {
            return NativeLibrary.GetExport(library, name);
        }
        finally
        {
            NativeLibrary.Free(library); // the library stays loaded: the fixture holds it
        }
    }

    private static NativeCULong Id(ObjectHandle handle) => (NativeCULong)handle.ObjectId;

    private static CK_MECHANISM ToNative(Mechanism mechanism, MechanismParameterScope scope) => mechanism.Marshal(scope, out _);

    // ===== v3.0: a NULL mechanism ends the operation of its kind =============================================

    [Fact(SkipUnless = Available, SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + Available)]
    public void NullMechanism_EndsTheOperationOfItsKind()
    {
        Pkcs11SessionCore session = OpenSession();
        try
        {
            LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
            var sid = (NativeCULong)session.SessionId;
            nuint s = (nuint)(ulong)session.SessionId;
            var digestInit = (delegate* unmanaged<nuint, IntPtr, nuint>)Export("C_DigestInit");
            var signInit = (delegate* unmanaged<nuint, IntPtr, nuint, nuint>)Export("C_SignInit");
            var verifyInit = (delegate* unmanaged<nuint, IntPtr, nuint, nuint>)Export("C_VerifyInit");

            using var scope = new MechanismParameterScope();
            CK_MECHANISM sha256 = ToNative(new Mechanism(CKM.CKM_SHA256), scope);
            CK_MECHANISM ecdsa = ToNative(new Mechanism(CKM.CKM_ECDSA_SHA256), scope);
            var (pub, priv) = TestKeys.GenerateEcP256KeyPair(session);

            // Nothing active: ending it is a no-op.
            Assert.Equal(0u, (uint)digestInit(s, IntPtr.Zero));

            Assert.Equal(CKR.CKR_OK, lowLevel.C_DigestInit(sid, in sha256));
            Assert.Equal(0u, (uint)digestInit(s, IntPtr.Zero));
            Assert.Equal(CKR.CKR_OK, lowLevel.C_DigestInit(sid, in sha256));
            Assert.Equal(0u, (uint)digestInit(s, IntPtr.Zero));

            Assert.Equal(CKR.CKR_OK, lowLevel.C_SignInit(sid, in ecdsa, Id(priv)));
            // A NULL verify doesn't end the signing.
            Assert.Equal(0u, (uint)verifyInit(s, IntPtr.Zero, 0));
            Assert.Equal(CKR.CKR_OPERATION_ACTIVE, lowLevel.C_SignInit(sid, in ecdsa, Id(priv)));
            Assert.Equal(0u, (uint)signInit(s, IntPtr.Zero, 0));
            Assert.Equal(CKR.CKR_OK, lowLevel.C_SignInit(sid, in ecdsa, Id(priv)));
            Assert.Equal(0u, (uint)signInit(s, IntPtr.Zero, 0));

            Assert.Equal(CKR.CKR_OK, lowLevel.C_VerifyInit(sid, in ecdsa, Id(pub)));
            Assert.Equal(0u, (uint)verifyInit(s, IntPtr.Zero, 0));
            Assert.Equal(CKR.CKR_OK, lowLevel.C_VerifyInit(sid, in ecdsa, Id(pub)));
            Assert.Equal(0u, (uint)verifyInit(s, IntPtr.Zero, 0));
        }
        finally
        {
            Close(session);
        }
    }

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable))]
    public void NullMechanism_EndsEncryptionAndDecryption()
    {
        using Pkcs11Session session = ((IPkcs11Backend)_backend).OpenSession();
        using Pkcs11Key key = session.GenerateAesKey(bitLength: 128);
        LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
        var sid = (NativeCULong)session.Core.SessionId;
        nuint s = (nuint)(ulong)session.Core.SessionId;
        var encryptInit = (delegate* unmanaged<nuint, IntPtr, nuint, nuint>)Export("C_EncryptInit");
        var decryptInit = (delegate* unmanaged<nuint, IntPtr, nuint, nuint>)Export("C_DecryptInit");

        using var scope = new MechanismParameterScope();
        CK_MECHANISM cfb = ToNative(new Mechanism(CKM.CKM_AES_CFB128, new byte[16]), scope);

        Assert.Equal(CKR.CKR_OK, lowLevel.C_EncryptInit(sid, in cfb, Id(key.PrivateHandle)));
        Assert.Equal(0u, (uint)encryptInit(s, IntPtr.Zero, 0));
        Assert.Equal(CKR.CKR_OK, lowLevel.C_EncryptInit(sid, in cfb, Id(key.PrivateHandle)));
        Assert.Equal(0u, (uint)encryptInit(s, IntPtr.Zero, 0));

        Assert.Equal(CKR.CKR_OK, lowLevel.C_DecryptInit(sid, in cfb, Id(key.PrivateHandle)));
        Assert.Equal(0u, (uint)decryptInit(s, IntPtr.Zero, 0));
        Assert.Equal(CKR.CKR_OK, lowLevel.C_DecryptInit(sid, in cfb, Id(key.PrivateHandle)));
        Assert.Equal(0u, (uint)decryptInit(s, IntPtr.Zero, 0));
    }

    // ===== v3.0: C_GetInterface by name, version and flags ===================================================

    [StructLayout(LayoutKind.Sequential)]
    private struct Version
    {
        public byte Major;
        public byte Minor;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Interface
    {
        public byte* Name;
        public Version* FunctionList; // every function list starts with its CK_VERSION
        public nuint Flags;
    }

    [Theory(SkipUnless = Available, SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + Available)]
    [InlineData((byte)3, (byte)2)]
    [InlineData((byte)3, (byte)1)]
    [InlineData((byte)3, (byte)0)]
    [InlineData((byte)2, (byte)40)]
    public void GetInterface_ByVersion_ReturnsThatFunctionList(byte major, byte minor)
    {
        var getInterface = (delegate* unmanaged<byte*, Version*, Interface**, nuint, nuint>)Export("C_GetInterface");
        byte[] name = "PKCS 11\0"u8.ToArray();
        var version = new Version { Major = major, Minor = minor };
        Interface* found = null;

        fixed (byte* n = name)
            Assert.Equal(0u, (uint)getInterface(n, &version, &found, 0));

        Assert.Equal("PKCS 11", Marshal.PtrToStringUTF8((IntPtr)found->Name));
        Assert.Equal(major, found->FunctionList->Major);
        Assert.Equal(minor, found->FunctionList->Minor);
    }

    [Fact(SkipUnless = Available, SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + Available)]
    public void GetInterface_NullNameAndVersion_ReturnsTheNewest()
    {
        var getInterface = (delegate* unmanaged<byte*, Version*, Interface**, nuint, nuint>)Export("C_GetInterface");
        Interface* found = null;

        Assert.Equal(0u, (uint)getInterface(null, null, &found, 0));
        Assert.Equal((3, 2), (found->FunctionList->Major, found->FunctionList->Minor));
    }

    [Fact(SkipUnless = Available, SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + Available)]
    public void GetInterface_ItDoesntHave_IsRefused()
    {
        var getInterface = (delegate* unmanaged<byte*, Version*, Interface**, nuint, nuint>)Export("C_GetInterface");
        const nuint ForkSafe = 1; // CKF_INTERFACE_FORK_SAFE
        byte[] standard = "PKCS 11\0"u8.ToArray();
        byte[] vendor = "Vendor TPM2\0"u8.ToArray();
        var unknown = new Version { Major = 3, Minor = 9 };
        Interface* found = null;

        fixed (byte* s = standard)
        fixed (byte* v = vendor)
        {
            Assert.Equal((uint)CKR.CKR_ARGUMENTS_BAD, (uint)getInterface(v, null, &found, 0));
            Assert.Equal((uint)CKR.CKR_ARGUMENTS_BAD, (uint)getInterface(s, &unknown, &found, 0));
            // No interface is fork safe: a child can't use the parent's TPM connection.
            Assert.Equal((uint)CKR.CKR_ARGUMENTS_BAD, (uint)getInterface(s, null, &found, ForkSafe));
            Assert.Equal((uint)CKR.CKR_ARGUMENTS_BAD, (uint)getInterface(s, null, null, 0));
        }
    }

    // ===== v3.0: C_LoginUser without a user name ================================================================

    [Fact(SkipUnless = Available, SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + Available)]
    public void LoginUser_WithoutAUserName_LogsIn()
    {
        Pkcs11Slot slot = _backend.Library.GetSlotList().First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId);
        using Pkcs11SessionCore session = slot.OpenSessionCore();
        LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
        var sid = (NativeCULong)session.SessionId;

        Assert.Equal(CKR.CKR_OK, lowLevel.C_LoginUser(sid, CKU.CKU_USER, _backend.UserPin.Span, ReadOnlySpan<byte>.Empty));
        Assert.Equal(CKR.CKR_OK, lowLevel.C_Logout(sid));
        Assert.Equal(CKR.CKR_PIN_INCORRECT, lowLevel.C_LoginUser(sid, CKU.CKU_USER, "not the PIN"u8, ReadOnlySpan<byte>.Empty));
    }

    // ===== v3.2: C_VerifySignature ends as the standard says ====================================================

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable))]
    public void VerifySignature_AfterAnUpdate_IsRefusedAndEnds()
    {
        Pkcs11SessionCore session = OpenSession();
        try
        {
            LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
            var sid = (NativeCULong)session.SessionId;
            var (pub, priv) = TestKeys.GenerateEcP256KeyPair(session);
            var mechanism = new Mechanism(CKM.CKM_ECDSA_SHA256);
            byte[] data = Encoding.UTF8.GetBytes("verify signature after an update");
            byte[] signature = session.Sign(mechanism, priv, data);
            using var scope = new MechanismParameterScope();
            CK_MECHANISM ck = ToNative(mechanism, scope);

            Assert.Equal(CKR.CKR_OK, lowLevel.C_VerifySignatureInit(sid, in ck, Id(pub), signature));
            Assert.Equal(CKR.CKR_OK, lowLevel.C_VerifySignatureUpdate(sid, data));
            Assert.Equal(CKR.CKR_OPERATION_NOT_INITIALIZED, lowLevel.C_VerifySignature(sid, data));
            // It ended: final has nothing to finish, and a new one starts.
            Assert.Equal(CKR.CKR_OPERATION_NOT_INITIALIZED, lowLevel.C_VerifySignatureFinal(sid));

            Assert.Equal(CKR.CKR_OK, lowLevel.C_VerifySignatureInit(sid, in ck, Id(pub), ReadOnlySpan<byte>.Empty));
            Assert.Equal(CKR.CKR_SIGNATURE_INVALID, lowLevel.C_VerifySignature(sid, data));
            Assert.Equal(CKR.CKR_OPERATION_NOT_INITIALIZED, lowLevel.C_VerifySignatureFinal(sid));
        }
        finally
        {
            Close(session);
        }
    }

    // ===== C_CloseAllSessions ====================================================================================

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SessionKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.SessionKeyPairsAvailable))]
    public void CloseAllSessions_ClosesEverySessionAndDestroysTheirObjects()
    {
        // The login is the token's: the second session shares it.
        Pkcs11SessionCore first = OpenSession();
        Pkcs11SessionCore second = _backend.Library.GetSlotList()
            .First(s => (NativeCULong)s.SlotId.Value == _backend.SlotId).OpenSessionCore();
        string label = $"close-all-{Guid.NewGuid():N}";
        using (var labelAttr = new ObjectAttribute(CKA.CKA_LABEL, label))
        using (var cls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY))
        using (var type = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC))
        using (var token = new ObjectAttribute(CKA.CKA_TOKEN, false))
        using (var verify = new ObjectAttribute(CKA.CKA_VERIFY, true))
        using (var ecParams = new ObjectAttribute(CKA.CKA_EC_PARAMS, TestKeys.EcP256Oid))
        using (var pcls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY))
        using (var ptoken = new ObjectAttribute(CKA.CKA_TOKEN, false))
        using (var plabel = new ObjectAttribute(CKA.CKA_LABEL, label))
        using (var sign = new ObjectAttribute(CKA.CKA_SIGN, true))
        {
            first.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), [cls, type, token, verify, ecParams, labelAttr],
                [pcls, type, ptoken, plabel, sign], out _, out _);
        }

        Assert.Equal(CKR.CKR_OK, _backend.Library.LowLevelLibrary!.C_CloseAllSessions(_backend.SlotId));

        Assert.Equal(CKR.CKR_SESSION_HANDLE_INVALID, Rv(() => first.GetSessionInfo()));
        Assert.Equal(CKR.CKR_SESSION_HANDLE_INVALID, Rv(() => second.GetSessionInfo()));
        first.Dispose();
        second.Dispose();

        Pkcs11SessionCore third = OpenSession();
        try
        {
            using var find = new ObjectAttribute(CKA.CKA_LABEL, label);
            Assert.Empty(third.FindAllObjects([find]));
        }
        finally
        {
            Close(third);
        }
    }

    // ===== ECDH: the peer point raw or DER-encoded ==============================================================

    public static TheoryData<string, bool> PeerPoints => new()
    {
        { "P-256", false }, { "P-256", true },
        { "P-384", false }, { "P-384", true },
        // P-521's 133-byte point takes a long-form DER length (0x81 0x85).
        { "P-521", false }, { "P-521", true },
    };

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable))]
    [MemberData(nameof(PeerPoints))]
    public void Ecdh_PeerPointRawOrDer_DerivesTheSecretDotNetComputes(string curve, bool der)
    {
        _backend.SkipUnlessCurve(curve);
        Pkcs11SessionCore session = OpenSession();
        try
        {
            // CKD_NULL and reading the secret back are what the default policy refuses, rightly: here the
            // secret is the result under test.
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            ECCurve named = Curve(curve);
            var (pub, priv) = GenerateEcdhKeyPair(session, TestKeys.EcParams(curve));
            using ECDiffieHellman peer = ECDiffieHellman.Create(named);
            ECParameters p = peer.ExportParameters(false);
            byte[] raw = [0x04, .. p.Q.X!, .. p.Q.Y!];

            ObjectHandle secret = Derive(session, priv, der ? Der(raw) : raw, (ulong)p.Q.X!.Length);
            using var value = session.GetAttributeValue(secret, [CKA.CKA_VALUE]);

            // The token's public key, to compute the same secret with .NET.
            using var point = session.GetAttributeValue(pub, [CKA.CKA_EC_POINT]);
            byte[] tokenRaw = Unwrap(point[0].GetValueAsByteArray()!);
            int n = p.Q.X!.Length;
            using ECDiffieHellman token = ECDiffieHellman.Create(new ECParameters
            {
                Curve = named,
                Q = new ECPoint { X = tokenRaw[1..(1 + n)], Y = tokenRaw[(1 + n)..] },
            });
            byte[] expected = peer.DeriveRawSecretAgreement(token.PublicKey);

            Assert.Equal(expected, value[0].GetValueAsByteArray());
        }
        finally
        {
            Close(session);
        }
    }

    public static TheoryData<string, byte[]> BadPeerPoints => new()
    {
        { "short raw point", [0x04, .. new byte[63]] },
        { "compressed point", [0x02, .. new byte[32]] },
        { "DER length too short", [0x04, 0x40, 0x04, .. new byte[63]] },
        { "DER length past the data", [0x04, 0x42, 0x04, .. new byte[64]] },
        { "DER long form, no length octets", [0x04, 0x80, 0x04, .. new byte[64]] },
        { "DER around a compressed point", [0x04, 0x41, 0x02, .. new byte[64]] },
    };

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable))]
    [MemberData(nameof(BadPeerPoints))]
    public void Ecdh_MalformedPeerPoint_IsRefused(string why, byte[] point)
    {
        _ = why;
        Pkcs11SessionCore session = OpenSession();
        try
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure); // CKD_NULL
            var (_, priv) = GenerateEcdhKeyPair(session, TestKeys.EcP256Oid);
            Assert.Equal(CKR.CKR_MECHANISM_PARAM_INVALID, Rv(() => Derive(session, priv, point, 32)));
        }
        finally
        {
            Close(session);
        }
    }

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable))]
    public void Ecdh_TemplateOrKdfItCantHonour_IsRefused()
    {
        Pkcs11SessionCore session = OpenSession();
        try
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure); // CKD_NULL
            var (_, priv) = GenerateEcdhKeyPair(session, TestKeys.EcP256Oid);
            using ECDiffieHellman peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            ECParameters p = peer.ExportParameters(false);
            byte[] raw = [0x04, .. p.Q.X!, .. p.Q.Y!];

            // The derived key is a generic secret held as its value.
            Assert.Equal(CKR.CKR_ATTRIBUTE_VALUE_INVALID, Rv(() => Derive(session, priv, raw, 32, CKO.CKO_PRIVATE_KEY)));
            Assert.Equal(CKR.CKR_ATTRIBUTE_VALUE_INVALID, Rv(() => Derive(session, priv, raw, 32, keyType: CKK.CKK_AES)));
            // Only CKD_NULL.
            Assert.Equal(CKR.CKR_MECHANISM_PARAM_INVALID, Rv(() => Derive(session, priv, raw, 32, kdf: CKD.CKD_SHA256_KDF)));
        }
        finally
        {
            Close(session);
        }
    }

    private static ECCurve Curve(string curve) => curve switch
    {
        "P-256" => ECCurve.NamedCurves.nistP256,
        "P-384" => ECCurve.NamedCurves.nistP384,
        _ => ECCurve.NamedCurves.nistP521,
    };

    private static (ObjectHandle pub, ObjectHandle priv) GenerateEcdhKeyPair(Pkcs11SessionCore session, byte[] ecParams)
    {
        using var cls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var type = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
        using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var parameters = new ObjectAttribute(CKA.CKA_EC_PARAMS, ecParams);
        using var pcls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var derive = new ObjectAttribute(CKA.CKA_DERIVE, true);
        using var sign = new ObjectAttribute(CKA.CKA_SIGN, false);
        session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), [cls, type, token, parameters],
            [pcls, type, token, derive, sign], out var pub, out var priv);
        return (pub, priv);
    }

    private static ObjectHandle Derive(Pkcs11SessionCore session, ObjectHandle priv, byte[] peer, ulong length,
        CKO cls = CKO.CKO_SECRET_KEY, CKK keyType = CKK.CKK_GENERIC_SECRET, CKD kdf = CKD.CKD_NULL)
    {
        using var c = new ObjectAttribute(CKA.CKA_CLASS, cls);
        using var t = new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType);
        using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var sensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
        using var extractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
        using var len = new ObjectAttribute(CKA.CKA_VALUE_LEN, length);
        return session.DeriveKey(new Mechanism(CKM.CKM_ECDH1_DERIVE, new CkmEcdh1DeriveParams(kdf, peer)), priv,
            [c, t, token, sensitive, extractable, len]);
    }

    /// <summary><paramref name="raw"/> as a DER OCTET STRING, with a long-form length past 127 bytes.</summary>
    private static byte[] Der(byte[] raw) => raw.Length < 0x80
        ? [0x04, (byte)raw.Length, .. raw]
        : [0x04, 0x81, (byte)raw.Length, .. raw];

    private static byte[] Unwrap(byte[] der) => der[1] == 0x81 ? der[3..] : der[2..];

    // ===== CKM_ECDSA: a digest of any length signs as ECDSA defines ============================================

    public static TheoryData<string, int> DigestLengths => new()
    {
        { "P-256", 20 }, { "P-256", 28 }, { "P-256", 16 }, { "P-256", 48 }, { "P-256", 64 },
        { "P-384", 20 }, { "P-384", 28 }, { "P-384", 64 },
        { "P-521", 28 }, { "P-521", 48 },
    };

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable))]
    [MemberData(nameof(DigestLengths))]
    public void Ecdsa_DigestOfAnyLength_VerifiesUnderDotNet(string curve, int digestLength)
    {
        _backend.SkipUnlessCurve(curve);
        Pkcs11SessionCore session = OpenSession();
        try
        {
            var (pub, priv) = TestKeys.GenerateEcKeyPair(session, TestKeys.EcParams(curve));
            byte[] digest = RandomNumberGenerator.GetBytes(digestLength);
            digest[0] |= 0x80; // the leftmost bits matter: a leading zero would hide a misplaced truncation

            byte[] signature = session.Sign(new Mechanism(CKM.CKM_ECDSA), priv, digest);

            using ECDsa token = TokenEcDsa(session, pub, Curve(curve));
            Assert.True(token.VerifyHash(digest, signature));
        }
        finally
        {
            Close(session);
        }
    }

    // P-521's order is longer than any digest: it needs the digest's own hash, which a TPM may not have.
    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.SignOnlyKeyPairsAvailable))]
    public void Ecdsa_P521Sha512Digest_SignsOnlyWithTheTpmsSha512()
    {
        _backend.SkipUnlessCurve("P-521");
        Pkcs11SessionCore session = OpenSession();
        try
        {
            var (pub, priv) = TestKeys.GenerateEcKeyPair(session, TestKeys.EcP521Oid);
            byte[] digest = RandomNumberGenerator.GetBytes(64);

            if (!_backend.TpmImplementsSha512)
            {
                Assert.Equal(CKR.CKR_DATA_LEN_RANGE, Rv(() => session.Sign(new Mechanism(CKM.CKM_ECDSA), priv, digest)));
                return;
            }

            byte[] signature = session.Sign(new Mechanism(CKM.CKM_ECDSA), priv, digest);
            using ECDsa token = TokenEcDsa(session, pub, ECCurve.NamedCurves.nistP521);
            Assert.True(token.VerifyHash(digest, signature));
        }
        finally
        {
            Close(session);
        }
    }

    private static ECDsa TokenEcDsa(Pkcs11SessionCore session, ObjectHandle pub, ECCurve curve)
    {
        using var point = session.GetAttributeValue(pub, [CKA.CKA_EC_POINT]);
        byte[] raw = Unwrap(point[0].GetValueAsByteArray()!);
        int n = (raw.Length - 1) / 2;
        return ECDsa.Create(new ECParameters { Curve = curve, Q = new ECPoint { X = raw[1..(1 + n)], Y = raw[(1 + n)..] } });
    }

    // ===== A key pair the store refuses, after the TPM made it, leaves nothing behind ==========================

    [Fact(SkipUnless = Available, SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + Available)]
    [SupportedOSPlatform("linux")] // as the backend
    public void KeyPairTheStoreRefuses_LeavesNoObjectAndNoTpmSlot()
    {
        string store = Environment.GetEnvironmentVariable("TPM2_PKCS11_STORE")
            ?? throw new InvalidOperationException("The fixture sets TPM2_PKCS11_STORE.");
        Pkcs11SessionCore session = OpenSession();
        try
        {
            string label = $"unstored-{Guid.NewGuid():N}";

            // The whole store read-only: SQLite writes a journal next to its file for each change, and FAPI
            // rewrites the token's seal object, which holds its objects, so writing a token object fails,
            // after the TPM has made the key pair. Directories last, so their files can still be reached.
            string[] entries =
            [
                .. Directory.GetFiles(store, "*", SearchOption.AllDirectories),
                .. Directory.GetDirectories(store, "*", SearchOption.AllDirectories).Reverse(),
                store,
            ];
            UnixFileMode[] modes = [.. entries.Select(File.GetUnixFileMode)];
            CKR first;
            try
            {
                foreach (string entry in entries)
                    File.SetUnixFileMode(entry, UnixFileMode.UserRead | (Directory.Exists(entry) ? UnixFileMode.UserExecute : 0));
                first = Rv(() => GenerateLabelledEcKeyPair(session, label, token: true));

                // More attempts than tpm2-abrmd (100) or fwTPM (128) has slots: a pair of loaded objects leaked
                // per attempt would fail the later ones, and the generation after them.
                for (int i = 1; first != CKR.CKR_OK && i < 70; i++)
                    Assert.Equal(first, Rv(() => GenerateLabelledEcKeyPair(session, label, token: true)));
            }
            finally
            {
                for (int i = entries.Length - 1; i >= 0; i--)
                    File.SetUnixFileMode(entries[i], modes[i]);
            }
            Assert.SkipWhen(first == CKR.CKR_OK, "The store took the write regardless (running as root?).");

            using (var find = new ObjectAttribute(CKA.CKA_LABEL, label))
                Assert.Empty(session.FindAllObjects([find]));

            GenerateLabelledEcKeyPair(session, label, token: false);
            using (var find = new ObjectAttribute(CKA.CKA_LABEL, label))
                Assert.Equal(2, session.FindAllObjects([find]).Count);
        }
        finally
        {
            Close(session);
        }
    }

    private static void GenerateLabelledEcKeyPair(Pkcs11SessionCore session, string label, bool token)
    {
        using var cls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var type = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
        using var onToken = new ObjectAttribute(CKA.CKA_TOKEN, token);
        using var labelAttr = new ObjectAttribute(CKA.CKA_LABEL, label);
        using var parameters = new ObjectAttribute(CKA.CKA_EC_PARAMS, TestKeys.EcP256Oid);
        using var pcls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        using var sign = new ObjectAttribute(CKA.CKA_SIGN, true);
        session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), [cls, type, onToken, labelAttr, parameters],
            [pcls, type, onToken, labelAttr, sign], out _, out _);
    }

    // ===== Key-pair templates it can't honour ===================================================================

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SessionKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.SessionKeyPairsAvailable))]
    public void KeyPairUsage_ItCantHonour_IsRefused()
    {
        Pkcs11SessionCore session = OpenSession();
        try
        {
            // RSA keys can't derive.
            Assert.Equal(CKR.CKR_ATTRIBUTE_VALUE_INVALID,
                Rv(() => GenerateRsaKeyPair(session, (CKA.CKA_SIGN, true), (CKA.CKA_DERIVE, true))));
            // A key that can do nothing.
            Assert.Equal(CKR.CKR_TEMPLATE_INCONSISTENT,
                Rv(() => GenerateRsaKeyPair(session, (CKA.CKA_SIGN, false), (CKA.CKA_DECRYPT, false))));
            // An EC key decrypts only as ECDH, which CKA_DERIVE=false refuses.
            Assert.Equal(CKR.CKR_TEMPLATE_INCONSISTENT,
                Rv(() => GenerateEcKeyPair(session, (CKA.CKA_DECRYPT, true), (CKA.CKA_DERIVE, false))));
            Assert.Equal(CKR.CKR_TEMPLATE_INCONSISTENT,
                Rv(() => GenerateEcKeyPair(session, (CKA.CKA_SIGN, false), (CKA.CKA_DERIVE, false))));
            // What only the token sets (PKCS#11: not in a template), whatever the value.
            foreach (CKA tokenSet in new[] { CKA.CKA_LOCAL, CKA.CKA_ALWAYS_SENSITIVE, CKA.CKA_NEVER_EXTRACTABLE })
            {
                Assert.Equal(CKR.CKR_ATTRIBUTE_READ_ONLY, Rv(() => GenerateEcKeyPair(session, (CKA.CKA_SIGN, true), (tokenSet, true))));
                Assert.Equal(CKR.CKR_ATTRIBUTE_READ_ONLY, Rv(() => GenerateEcKeyPair(session, (CKA.CKA_SIGN, true), (tokenSet, false))));
            }
        }
        finally
        {
            Close(session);
        }
    }

    private static void GenerateRsaKeyPair(Pkcs11SessionCore session, params (CKA type, bool value)[] privateUsage)
    {
        using var cls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var type = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
        using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var bits = new ObjectAttribute(CKA.CKA_MODULUS_BITS, 2048UL);
        using var pcls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        List<ObjectAttribute> priv = [pcls, type, token, .. privateUsage.Select(u => new ObjectAttribute(u.type, u.value))];
        try
        {
            session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), [cls, type, token, bits], priv, out _, out _);
        }
        finally
        {
            foreach (var a in priv.Skip(3))
                a.Dispose();
        }
    }

    private static void GenerateEcKeyPair(Pkcs11SessionCore session, params (CKA type, bool value)[] privateUsage)
    {
        using var cls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
        using var type = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
        using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var parameters = new ObjectAttribute(CKA.CKA_EC_PARAMS, TestKeys.EcP256Oid);
        using var pcls = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
        List<ObjectAttribute> priv = [pcls, type, token, .. privateUsage.Select(u => new ObjectAttribute(u.type, u.value))];
        try
        {
            session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), [cls, type, token, parameters], priv, out _, out _);
        }
        finally
        {
            foreach (var a in priv.Skip(3))
                a.Dispose();
        }
    }

    // ===== Using a key for what it doesn't allow ================================================================

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.DeriveOnlyKeyPairsAvailable))]
    public void SignOrVerifyWithAKeyThatDoesntAllowIt_IsRefused()
    {
        Pkcs11SessionCore session = OpenSession();
        try
        {
            LowLevelPkcs11Library lowLevel = _backend.Library.LowLevelLibrary!;
            var sid = (NativeCULong)session.SessionId;
            using var scope = new MechanismParameterScope();
            CK_MECHANISM ecdsa = ToNative(new Mechanism(CKM.CKM_ECDSA_SHA256), scope);

            // An ECDH key pair: the private key doesn't sign, the public key doesn't verify.
            var (pub, priv) = GenerateEcdhKeyPair(session, TestKeys.EcP256Oid);
            Assert.Equal(CKR.CKR_KEY_FUNCTION_NOT_PERMITTED, lowLevel.C_SignInit(sid, in ecdsa, Id(priv)));
            Assert.Equal(CKR.CKR_KEY_FUNCTION_NOT_PERMITTED, lowLevel.C_VerifyInit(sid, in ecdsa, Id(pub)));
            Assert.Equal(CKR.CKR_KEY_FUNCTION_NOT_PERMITTED, lowLevel.C_VerifySignatureInit(sid, in ecdsa, Id(pub), new byte[64]));
            // Nothing was left active.
            CK_MECHANISM sha256 = ToNative(new Mechanism(CKM.CKM_SHA256), scope);
            Assert.Equal(CKR.CKR_OK, lowLevel.C_DigestInit(sid, in sha256));
        }
        finally
        {
            Close(session);
        }
    }

    // ===== Secret-key templates it can't honour =================================================================

    public static TheoryData<string, CKR, (CKA, object)[]> AesTemplates => new()
    {
        { "no CKA_VALUE_LEN", CKR.CKR_TEMPLATE_INCOMPLETE, [] },
        { "20-byte key", CKR.CKR_ATTRIBUTE_VALUE_INVALID, [(CKA.CKA_VALUE_LEN, 20UL)] },
        { "another class", CKR.CKR_TEMPLATE_INCONSISTENT, [(CKA.CKA_VALUE_LEN, 16UL), (CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY)] },
        { "another key type", CKR.CKR_TEMPLATE_INCONSISTENT, [(CKA.CKA_VALUE_LEN, 16UL), (CKA.CKA_KEY_TYPE, CKK.CKK_DES3)] },
        { "a value to generate", CKR.CKR_TEMPLATE_INCONSISTENT, [(CKA.CKA_VALUE_LEN, 16UL), (CKA.CKA_VALUE, new byte[16])] },
        { "an AES MAC", CKR.CKR_ATTRIBUTE_VALUE_INVALID, [(CKA.CKA_VALUE_LEN, 16UL), (CKA.CKA_SIGN, true)] },
        { "an AES MAC to verify", CKR.CKR_ATTRIBUTE_VALUE_INVALID, [(CKA.CKA_VALUE_LEN, 16UL), (CKA.CKA_VERIFY, true)] },
        { "wrapping", CKR.CKR_ATTRIBUTE_VALUE_INVALID, [(CKA.CKA_VALUE_LEN, 16UL), (CKA.CKA_WRAP, true)] },
        { "unwrapping", CKR.CKR_ATTRIBUTE_VALUE_INVALID, [(CKA.CKA_VALUE_LEN, 16UL), (CKA.CKA_UNWRAP, true)] },
        { "extractable", CKR.CKR_ATTRIBUTE_VALUE_INVALID, [(CKA.CKA_VALUE_LEN, 16UL), (CKA.CKA_EXTRACTABLE, true)] },
        { "not sensitive", CKR.CKR_ATTRIBUTE_VALUE_INVALID, [(CKA.CKA_VALUE_LEN, 16UL), (CKA.CKA_SENSITIVE, false)] },
        { "CKA_LOCAL, which the token sets", CKR.CKR_ATTRIBUTE_READ_ONLY, [(CKA.CKA_VALUE_LEN, 16UL), (CKA.CKA_LOCAL, true)] },
        { "CKA_KEY_GEN_MECHANISM, which the token sets", CKR.CKR_ATTRIBUTE_READ_ONLY, [(CKA.CKA_VALUE_LEN, 16UL), (CKA.CKA_KEY_GEN_MECHANISM, (ulong)CKM.CKM_AES_KEY_GEN)] },
    };

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable))]
    [MemberData(nameof(AesTemplates))]
    public void GenerateKey_AesTemplateItCantHonour_IsRefused(string why, CKR expected, (CKA, object)[] template)
    {
        _ = why;
        Pkcs11SessionCore session = OpenSession();
        try
        {
            // The library refuses CKA_SENSITIVE=false itself by default; the token's refusal is under test.
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            Assert.Equal(expected, Rv(() => GenerateAes(session, new Mechanism(CKM.CKM_AES_KEY_GEN), template)));
        }
        finally
        {
            Close(session);
        }
    }

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.SecretKeyGenerationAvailable))]
    public void GenerateKey_MechanismItCantHonour_IsRefused()
    {
        Pkcs11SessionCore session = OpenSession();
        try
        {
            (CKA, object)[] aes128 = [(CKA.CKA_VALUE_LEN, 16UL)];
            Assert.Equal(CKR.CKR_MECHANISM_INVALID, Rv(() => GenerateAes(session, new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), aes128)));
            Assert.Equal(CKR.CKR_MECHANISM_PARAM_INVALID, Rv(() => GenerateAes(session, new Mechanism(CKM.CKM_AES_KEY_GEN, new byte[8]), aes128)));
        }
        finally
        {
            Close(session);
        }
    }

    public static TheoryData<string, CKR, (CKA, object?)[]> HmacImports => new()
    {
        { "an HMAC key to encrypt", CKR.CKR_ATTRIBUTE_VALUE_INVALID, [(CKA.CKA_ENCRYPT, true)] },
        { "an HMAC key to decrypt", CKR.CKR_ATTRIBUTE_VALUE_INVALID, [(CKA.CKA_DECRYPT, true)] },
        { "no value", CKR.CKR_TEMPLATE_INCOMPLETE, [(CKA.CKA_VALUE, null)] },
        { "an empty value", CKR.CKR_ATTRIBUTE_VALUE_INVALID, [(CKA.CKA_VALUE, Array.Empty<byte>())] },
        { "a CKA_VALUE_LEN that isn't the value's", CKR.CKR_TEMPLATE_INCONSISTENT, [(CKA.CKA_VALUE_LEN, 16UL)] },
    };

    [Theory(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.ImportedSecretKeysAvailable))]
    [MemberData(nameof(HmacImports))]
    public void CreateObject_HmacKeyItCantHonour_IsRefused(string why, CKR expected, (CKA, object?)[] template)
    {
        _ = why;
        Pkcs11SessionCore session = OpenSession();
        try
        {
            Assert.Equal(expected, Rv(() => ImportHmac(session, template)));
        }
        finally
        {
            Close(session);
        }
    }

    private static ObjectAttribute Attr(CKA type, object value) => value switch
    {
        bool b => new ObjectAttribute(type, b),
        ulong u => new ObjectAttribute(type, u),
        CKO o => new ObjectAttribute(type, o),
        CKK k => new ObjectAttribute(type, k),
        byte[] bytes => new ObjectAttribute(type, bytes),
        _ => throw new ArgumentException($"No attribute for {value?.GetType()}", nameof(value)),
    };

    private static ObjectHandle GenerateAes(Pkcs11SessionCore session, Mechanism mechanism, (CKA type, object value)[] template)
    {
        var defaults = new List<(CKA, object)> { (CKA.CKA_CLASS, CKO.CKO_SECRET_KEY), (CKA.CKA_KEY_TYPE, CKK.CKK_AES), (CKA.CKA_TOKEN, false) };
        defaults.RemoveAll(d => template.Any(t => t.type == d.Item1));
        List<ObjectAttribute> attrs = [.. defaults.Concat(template).Select(a => Attr(a.Item1, a.Item2))];
        try
        {
            return session.GenerateKey(mechanism, attrs);
        }
        finally
        {
            foreach (var a in attrs)
                a.Dispose();
        }
    }

    private static ObjectHandle ImportHmac(Pkcs11SessionCore session, (CKA type, object? value)[] template)
    {
        var defaults = new List<(CKA, object?)>
        {
            (CKA.CKA_CLASS, CKO.CKO_SECRET_KEY), (CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET), (CKA.CKA_TOKEN, false),
            (CKA.CKA_SIGN, true), (CKA.CKA_VALUE, RandomNumberGenerator.GetBytes(32)),
        };
        defaults.RemoveAll(d => template.Any(t => t.type == d.Item1));
        List<ObjectAttribute> attrs = [.. defaults.Concat(template).Where(a => a.Item2 is not null).Select(a => Attr(a.Item1, a.Item2!))];
        try
        {
            return session.CreateObject(attrs);
        }
        finally
        {
            foreach (var a in attrs)
                a.Dispose();
        }
    }
}
