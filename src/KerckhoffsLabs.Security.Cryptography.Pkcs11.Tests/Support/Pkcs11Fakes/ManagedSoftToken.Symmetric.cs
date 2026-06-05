using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// Symmetric family: single-part C_EncryptInit/C_Encrypt (+ Decrypt) over the BCL — block ciphers
// (AES/DES/3DES/RC2, CBC/ECB) and AEAD (AES-GCM/CCM, ChaCha20-Poly1305). Because the token reports
// IsMessageApiSupported=false, the AEAD adapters take their v2.40 single-part path where the output
// is ciphertext ‖ tag — which is exactly what this produces/consumes.
internal sealed partial class ManagedSoftToken
{
    private readonly Dictionary<ulong, SymOp> _ops = [];

    private readonly record struct SymOp(
        ulong Mechanism, byte[] Key, byte[]? Iv, byte[]? Aad, int TagLen, int Rc2EffectiveBits);

    // RSA encryption (CKM_RSA_PKCS / CKM_RSA_PKCS_OAEP) routes to the asymmetric path in
    // ManagedSoftToken.RsaCipher.cs; everything else is a symmetric cipher.
    public override CKR C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
        => IsRsaCipher((CKM)(ulong)mechanism.Mechanism)
            ? InitRsaCipher((ulong)session, ref mechanism, (ulong)key)
            : InitSym((ulong)session, ref mechanism, (ulong)key);

    public override CKR C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
        => IsRsaCipher((CKM)(ulong)mechanism.Mechanism)
            ? InitRsaCipher((ulong)session, ref mechanism, (ulong)key)
            : InitSym((ulong)session, ref mechanism, (ulong)key);

    public override CKR C_Encrypt(NativeCULong session, byte[] data, NativeCULong dataLen, byte[]? encryptedData, ref NativeCULong encryptedDataLen)
        => _rsaEncOps.ContainsKey((ulong)session)
            ? RsaTransform((ulong)session, data, (int)dataLen, encryptedData, ref encryptedDataLen, encrypt: true)
            : TransformSym((ulong)session, data, (int)dataLen, encryptedData, ref encryptedDataLen, encrypt: true);

    public override CKR C_Decrypt(NativeCULong session, byte[] encryptedData, NativeCULong encryptedDataLen, byte[]? data, ref NativeCULong dataLen)
        => _rsaEncOps.ContainsKey((ulong)session)
            ? RsaTransform((ulong)session, encryptedData, (int)encryptedDataLen, data, ref dataLen, encrypt: false)
            : TransformSym((ulong)session, encryptedData, (int)encryptedDataLen, data, ref dataLen, encrypt: false);

    private CKR InitSym(ulong session, ref CK_MECHANISM mech, ulong key)
    {
        if (!_sessions.Contains(session)) return CKR.CKR_SESSION_HANDLE_INVALID;
        if (!_objects.TryGetValue(key, out var obj) || !obj.TryGetValue((ulong)CKA.CKA_VALUE, out var keyVal))
            return CKR.CKR_KEY_HANDLE_INVALID;

        var m = (CKM)(ulong)mech.Mechanism;
        byte[]? iv = null, aad = null;
        int tagLen = 0, rc2Bits = 0;

        switch (m)
        {
            case CKM.CKM_AES_GCM:
                {
                    var p = UnmanagedMemory.Read<CK_GCM_PARAMS>(mech.Parameter);
                    iv = ReadPtr(p.Iv, (int)p.IvLen);
                    aad = ReadPtr(p.AAD, (int)p.AADLen);
                    tagLen = (int)p.TagBits / 8;
                    break;
                }
            case CKM.CKM_AES_CCM:
                {
                    var p = UnmanagedMemory.Read<CK_CCM_PARAMS>(mech.Parameter);
                    iv = ReadPtr(p.Nonce, (int)p.NonceLen);
                    aad = ReadPtr(p.AAD, (int)p.AADLen);
                    tagLen = (int)p.MACLen;
                    break;
                }
            case CKM.CKM_CHACHA20_POLY1305:
                {
                    var p = UnmanagedMemory.Read<CK_SALSA20_CHACHA20_POLY1305_PARAMS>(mech.Parameter);
                    iv = ReadPtr(p.Nonce, (int)p.NonceLen);
                    aad = ReadPtr(p.AAD, (int)p.AADLen);
                    tagLen = 16;
                    break;
                }
            case CKM.CKM_RC2_CBC:
            case CKM.CKM_RC2_CBC_PAD:
                {
                    var p = UnmanagedMemory.Read<CK_RC2_CBC_PARAMS>(mech.Parameter);
                    rc2Bits = (int)p.EffectiveBits;
                    iv = p.Iv; // inline 8-byte IV
                    break;
                }
            case CKM.CKM_RC2_ECB:
                {
                    var p = UnmanagedMemory.Read<CK_RC2_PARAMS>(mech.Parameter);
                    rc2Bits = (int)p.EffectiveBits;
                    break;
                }
            default:
                // Raw-IV block ciphers (AES/DES/3DES CBC carry the IV directly; ECB has no parameter).
                if (mech.Parameter != IntPtr.Zero && (int)mech.ParameterLen > 0)
                    iv = UnmanagedMemory.Read(mech.Parameter, (int)mech.ParameterLen);
                break;
        }

        _ops[session] = new SymOp((ulong)mech.Mechanism, keyVal, iv, aad, tagLen, rc2Bits);
        return CKR.CKR_OK;
    }

    private CKR TransformSym(ulong session, byte[] input, int inputLen, byte[]? output, ref NativeCULong outputLen, bool encrypt)
    {
        if (!_ops.TryGetValue(session, out var op)) return CKR.CKR_OPERATION_NOT_INITIALIZED;

        byte[] result;
        try
        {
            byte[] inBytes = input.AsSpan(0, inputLen).ToArray();
            result = IsAead((CKM)op.Mechanism)
                ? AeadTransform(op, inBytes, encrypt)
                : BlockTransform(op, inBytes, encrypt);
        }
        catch (PlatformNotSupportedException) { _ops.Remove(session); return CKR.CKR_MECHANISM_INVALID; }
        catch (CryptographicException) { _ops.Remove(session); return encrypt ? CKR.CKR_DATA_LEN_RANGE : CKR.CKR_ENCRYPTED_DATA_INVALID; }

        // Size probe / under-allocation: report the required length, keep the op live for retry.
        if (output is null) { outputLen = (NativeCULong)(ulong)result.Length; return CKR.CKR_OK; }
        if (output.Length < result.Length) { outputLen = (NativeCULong)(ulong)result.Length; return CKR.CKR_BUFFER_TOO_SMALL; }

        Array.Copy(result, output, result.Length);
        outputLen = (NativeCULong)(ulong)result.Length;
        _ops.Remove(session); // single-shot operation complete
        return CKR.CKR_OK;
    }

    private static byte[]? ReadPtr(IntPtr ptr, int len)
        => ptr != IntPtr.Zero && len > 0 ? UnmanagedMemory.Read(ptr, len) : null;

    // === Block ciphers (AES/DES/3DES/RC2 CBC/ECB) ========================

    private static byte[] BlockTransform(SymOp op, byte[] data, bool encrypt)
    {
        var mech = (CKM)op.Mechanism;
        using SymmetricAlgorithm alg = CreateBlockCipher(mech);
        var (mode, padding) = MapBlockMode(mech);
        alg.Key = op.Key;
        if (alg is RC2 rc2 && op.Rc2EffectiveBits > 0)
            rc2.EffectiveKeySize = op.Rc2EffectiveBits;
        alg.Mode = mode;
        alg.Padding = padding;
        if (mode == CipherMode.CBC)
            alg.IV = op.Iv ?? throw new CryptographicException("CBC requires an IV.");

        using ICryptoTransform t = encrypt ? alg.CreateEncryptor() : alg.CreateDecryptor();
        return t.TransformFinalBlock(data, 0, data.Length);
    }

    private static SymmetricAlgorithm CreateBlockCipher(CKM mech) => mech switch
    {
        CKM.CKM_AES_CBC or CKM.CKM_AES_CBC_PAD or CKM.CKM_AES_ECB => Aes.Create(),
        CKM.CKM_DES_CBC or CKM.CKM_DES_CBC_PAD or CKM.CKM_DES_ECB => DES.Create(),
        CKM.CKM_DES3_CBC or CKM.CKM_DES3_CBC_PAD or CKM.CKM_DES3_ECB => TripleDES.Create(),
        CKM.CKM_RC2_CBC or CKM.CKM_RC2_CBC_PAD or CKM.CKM_RC2_ECB => RC2.Create(),
        _ => throw new CryptographicException($"ManagedSoftToken: unsupported block mechanism {mech}."),
    };

    private static (CipherMode mode, PaddingMode padding) MapBlockMode(CKM mech) => mech switch
    {
        CKM.CKM_AES_CBC or CKM.CKM_DES_CBC or CKM.CKM_DES3_CBC or CKM.CKM_RC2_CBC
            => (CipherMode.CBC, PaddingMode.None),
        CKM.CKM_AES_CBC_PAD or CKM.CKM_DES_CBC_PAD or CKM.CKM_DES3_CBC_PAD or CKM.CKM_RC2_CBC_PAD
            => (CipherMode.CBC, PaddingMode.PKCS7),
        CKM.CKM_AES_ECB or CKM.CKM_DES_ECB or CKM.CKM_DES3_ECB or CKM.CKM_RC2_ECB
            => (CipherMode.ECB, PaddingMode.None),
        _ => throw new CryptographicException($"ManagedSoftToken: unsupported block mechanism {mech}."),
    };

    // === AEAD (AES-GCM/CCM, ChaCha20-Poly1305) ===========================

    private static bool IsAead(CKM m) => m is CKM.CKM_AES_GCM or CKM.CKM_AES_CCM or CKM.CKM_CHACHA20_POLY1305;

    private static byte[] AeadTransform(SymOp op, byte[] data, bool encrypt)
    {
        var mech = (CKM)op.Mechanism;
        byte[] nonce = op.Iv ?? throw new CryptographicException("AEAD requires a nonce.");
        byte[] aad = op.Aad ?? [];

        if (encrypt)
        {
            byte[] ct = new byte[data.Length];
            byte[] tag = new byte[op.TagLen];
            AeadEncrypt(mech, op.Key, nonce, data, ct, tag, aad);
            return [.. ct, .. tag]; // PKCS#11 v2.40 single-part: ciphertext ‖ tag
        }

        if (data.Length < op.TagLen) throw new CryptographicException("ciphertext shorter than tag.");
        int ctLen = data.Length - op.TagLen;
        byte[] cipher = data.AsSpan(0, ctLen).ToArray();
        byte[] authTag = data.AsSpan(ctLen).ToArray();
        byte[] pt = new byte[ctLen];
        AeadDecrypt(mech, op.Key, nonce, cipher, authTag, pt, aad);
        return pt;
    }

    private static void AeadEncrypt(CKM mech, byte[] key, byte[] nonce, byte[] pt, byte[] ct, byte[] tag, byte[] aad)
    {
        switch (mech)
        {
            case CKM.CKM_AES_GCM:
                using (var g = new AesGcm(key, tag.Length)) g.Encrypt(nonce, pt, ct, tag, aad);
                break;
            case CKM.CKM_AES_CCM:
                using (var c = new AesCcm(key)) c.Encrypt(nonce, pt, ct, tag, aad);
                break;
            case CKM.CKM_CHACHA20_POLY1305:
                using (var ch = new ChaCha20Poly1305(key)) ch.Encrypt(nonce, pt, ct, tag, aad);
                break;
            default:
                throw new CryptographicException($"ManagedSoftToken: unsupported AEAD {mech}.");
        }
    }

    private static void AeadDecrypt(CKM mech, byte[] key, byte[] nonce, byte[] ct, byte[] tag, byte[] pt, byte[] aad)
    {
        switch (mech)
        {
            case CKM.CKM_AES_GCM:
                using (var g = new AesGcm(key, tag.Length)) g.Decrypt(nonce, ct, tag, pt, aad);
                break;
            case CKM.CKM_AES_CCM:
                using (var c = new AesCcm(key)) c.Decrypt(nonce, ct, tag, pt, aad);
                break;
            case CKM.CKM_CHACHA20_POLY1305:
                using (var ch = new ChaCha20Poly1305(key)) ch.Decrypt(nonce, ct, tag, pt, aad);
                break;
            default:
                throw new CryptographicException($"ManagedSoftToken: unsupported AEAD {mech}.");
        }
    }
}
