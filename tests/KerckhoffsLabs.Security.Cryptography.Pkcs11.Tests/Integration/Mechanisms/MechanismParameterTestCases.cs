using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>
/// A mechanism parameter outside what PKCS#11 v3.2 allows is refused at the <c>C_*Init</c> that receives it,
/// checked on every real backend: the AES-GCM and AES-CCM parameter blocks with a NULL pointer behind a length
/// or a length out of its range.
/// </summary>
/// <remarks>
/// <para>
/// The library's parameter types refuse these values before any native call, so each case lays the
/// <c>CK_*_PARAMS</c> struct out itself, with pointers into unmanaged memory it owns, and passes it as a raw
/// block through the raw dispatch: the refusal is the module's. A module must not read through a NULL
/// pointer it was given a length for, so a crash is a finding, not a skip.
/// </para>
/// <para>
/// Every refused Init is followed, in the same session, by an Init with good parameters whose result is
/// checked against the BCL: the refusal started no operation (§5.2) and left nothing behind.
/// </para>
/// </remarks>
internal static class MechanismParameterTestCases
{
    private static readonly byte[] Message = "the quick brown fox jumps over the lazy dog"u8.ToArray();
    private static readonly byte[] Aad = "header.v1"u8.ToArray();

    private delegate CKR KeyedInit(NativeCULong session, in CK_MECHANISM mechanism, NativeCULong key);

    private static void AssertOk(CKR rv, string step) =>
        Assert.True(rv == CKR.CKR_OK, $"{step} was expected to succeed but returned {rv}.");

    private static void WithSession(IPkcs11Backend backend, Action<LowLevelPkcs11Library, NativeCULong, Pkcs11SessionCore> body)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            body(backend.Library.LowLevelLibrary!, (NativeCULong)session.SessionId, session);
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    private static CKR Init(KeyedInit init, NativeCULong sid, Mechanism mechanism, ObjectHandle key)
    {
        using var scope = new MechanismParameterScope();
        CK_MECHANISM mech = mechanism.Marshal(scope, out _);
        return init(sid, in mech, (NativeCULong)key.ObjectId);
    }

    // === AES-GCM and AES-CCM ================================================

    public static TheoryData<string> AeadParameterFaults =>
    [
        "GCM pIv NULL", "GCM ulIvLen 0", "GCM pAAD NULL", "GCM ulTagBits 136",
        "CCM pNonce NULL", "CCM ulNonceLen 6", "CCM ulNonceLen 14", "CCM pAAD NULL",
        "CCM ulMACLen 2", "CCM ulMACLen 5", "CCM ulMACLen 18",
    ];

    // PKCS#11 v3.2 §6.13.7: CK_GCM_PARAMS takes an IV of 1 to 2^32 - 1 bytes and a tag of 0 to 128 bits;
    // CK_CCM_PARAMS a nonce of 7 to 13 bytes and a MAC of 4, 6, 8, 10, 12, 14 or 16 bytes; and §6.13.2, §6.13.4
    // let pAAD be NULL only when ulAADLen is 0. C_EncryptInit and C_DecryptInit refuse a value outside that
    // with CKR_MECHANISM_PARAM_INVALID (§5.1.6: "invalid parameters were supplied to the mechanism"). A NULL
    // pointer behind a non-zero length may also be refused as CKR_ARGUMENTS_BAD, the code §5.1.6 gives for
    // arguments "in some way not appropriate"; nothing else is taken. After each refusal the same session runs
    // the Init again with good parameters, and its result is the BCL's.
    internal static void Assert_AeadParameter_OutOfRange_IsMechanismParamInvalid(IPkcs11Backend backend, string fault)
    {
        bool gcm = fault.StartsWith("GCM", StringComparison.Ordinal);
        CKM type = gcm ? CKM.CKM_AES_GCM : CKM.CKM_AES_CCM;
        backend.RequireMechanismFlags(type, f => f.Encrypt && f.Decrypt, "CKF_ENCRYPT and CKF_DECRYPT");
        bool nullPointer = fault.EndsWith("NULL", StringComparison.Ordinal);
        WithSession(backend, (lowLevel, sid, session) =>
        {
            byte[] rawKey = RandomNumberGenerator.GetBytes(32);
            ObjectHandle key = TestKeys.CreateAes256Key(session, rawKey);
            try
            {
                using var buffers = new NativeBuffers();
                byte[] nonce = RandomNumberGenerator.GetBytes(12);
                Mechanism bad = gcm ? Gcm(lowLevel, buffers, nonce, fault) : Ccm(buffers, nonce, fault);
                Mechanism good = gcm ? Gcm(lowLevel, buffers, nonce, fault: null) : Ccm(buffers, nonce, fault: null);
                byte[] expected = new byte[Message.Length + 16];
                if (gcm)
                {
                    using var bcl = new AesGcm(rawKey, 16);
                    bcl.Encrypt(nonce, Message, expected.AsSpan(0, Message.Length), expected.AsSpan(Message.Length), Aad);
                }
                else
                {
                    using var bcl = new AesCcm(rawKey);
                    bcl.Encrypt(nonce, Message, expected.AsSpan(0, Message.Length), expected.AsSpan(Message.Length), Aad);
                }

                foreach (bool encrypt in (bool[])[true, false])
                {
                    string op = encrypt ? "C_EncryptInit" : "C_DecryptInit";
                    KeyedInit init = encrypt ? lowLevel.C_EncryptInit : lowLevel.C_DecryptInit;
                    CKR rv = Init(init, sid, bad, key);
                    Assert.True(rv == CKR.CKR_MECHANISM_PARAM_INVALID || (nullPointer && rv == CKR.CKR_ARGUMENTS_BAD),
                        $"{op}({type}) with {fault} returned {rv}.");

                    AssertOk(Init(init, sid, good, key), $"{op}({type}) with good parameters after the refusal");
                    byte[] input = encrypt ? Message : expected;
                    byte[] output = new byte[expected.Length];
                    rv = encrypt
                        ? lowLevel.C_Encrypt(sid, input, output, lengthOnly: false, out NativeCULong written)
                        : lowLevel.C_Decrypt(sid, input, output, lengthOnly: false, out written);
                    AssertOk(rv, encrypt ? "C_Encrypt" : "C_Decrypt");
                    Assert.Equal(encrypt ? expected : Message, output.AsSpan(0, (int)(ulong)written).ToArray());
                }
            }
            finally { session.DestroyObject(key); }
        });
    }

    // A CK_GCM_PARAMS with a 12-byte IV, the AAD and a 128-bit tag, but for the fault. ulIvBits is the IV length
    // in bits for a module bound through a v3.x interface and 0 otherwise, as the library sends it.
    private static Mechanism Gcm(LowLevelPkcs11Library lowLevel, NativeBuffers buffers, byte[] iv, string? fault)
    {
        ulong ivLen = fault == "GCM ulIvLen 0" ? 0UL : (ulong)iv.Length;
        var parameter = new CK_GCM_PARAMS
        {
            Iv = fault == "GCM pIv NULL" ? IntPtr.Zero : buffers.Of(iv),
            IvLen = (NativeCULong)ivLen,
            IvBits = (NativeCULong)(lowLevel.IsBoundThroughV3Interface ? ivLen * 8 : 0UL),
            AAD = fault == "GCM pAAD NULL" ? IntPtr.Zero : buffers.Of(Aad),
            AADLen = (NativeCULong)(ulong)Aad.Length,
            TagBits = (NativeCULong)(fault == "GCM ulTagBits 136" ? 136UL : 128UL),
        };
        return RawParameter.From(CKM.CKM_AES_GCM, in parameter);
    }

    // A CK_CCM_PARAMS for the message, with a 12-byte nonce, the AAD and a 16-byte MAC, but for the fault. A nonce
    // of the wrong length is the first bytes of a longer one.
    private static Mechanism Ccm(NativeBuffers buffers, byte[] nonce, string? fault)
    {
        int nonceLen = fault switch { "CCM ulNonceLen 6" => 6, "CCM ulNonceLen 14" => 14, _ => nonce.Length };
        byte[] nonceBytes = [.. nonce, .. RandomNumberGenerator.GetBytes(2)];
        var parameter = new CK_CCM_PARAMS
        {
            DataLen = (NativeCULong)(ulong)Message.Length,
            Nonce = fault == "CCM pNonce NULL" ? IntPtr.Zero : buffers.Of(nonceBytes[..nonceLen]),
            NonceLen = (NativeCULong)(ulong)nonceLen,
            AAD = fault == "CCM pAAD NULL" ? IntPtr.Zero : buffers.Of(Aad),
            AADLen = (NativeCULong)(ulong)Aad.Length,
            MACLen = (NativeCULong)(fault switch { "CCM ulMACLen 2" => 2UL, "CCM ulMACLen 5" => 5UL, "CCM ulMACLen 18" => 18UL, _ => 16UL }),
        };
        return RawParameter.From(CKM.CKM_AES_CCM, in parameter);
    }
}
