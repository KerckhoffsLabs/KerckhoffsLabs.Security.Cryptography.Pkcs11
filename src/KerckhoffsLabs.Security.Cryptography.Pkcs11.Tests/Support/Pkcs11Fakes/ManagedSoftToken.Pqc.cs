using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

#pragma warning disable SYSLIB5006 // ML-DSA / SLH-DSA / ML-KEM are evaluation-only BCL APIs.

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// PQC family: C_GenerateKeyPair (ML-DSA / SLH-DSA / ML-KEM) + ML-KEM C_EncapsulateKey/C_DecapsulateKey.
// ML-DSA/SLH-DSA sign/verify dispatch from ManagedSoftToken.Sign.cs.
internal sealed partial class ManagedSoftToken
{
    private CKR GeneratePqcKeyPair(CKM mech, Dictionary<ulong, byte[]> pub, Dictionary<ulong, byte[]> priv,
        ref NativeCULong publicKey, ref NativeCULong privateKey)
    {
        ulong paramSet =
            pub.TryGetValue((ulong)CKA.CKA_PARAMETER_SET, out var ps) ? ToUlong(ps) :
            priv.TryGetValue((ulong)CKA.CKA_PARAMETER_SET, out var ps2) ? ToUlong(ps2) : 0;

        switch (mech)
        {
            case CKM.CKM_ML_DSA_KEY_PAIR_GEN:
            {
                var key = MLDsa.GenerateKey(MapMlDsa((CkpMlDsa)paramSet));
                StorePqc(CKK.CKK_ML_DSA, paramSet, key.ExportMLDsaPublicKey(), key, pub, priv, ref publicKey, ref privateKey);
                return CKR.CKR_OK;
            }
            case CKM.CKM_SLH_DSA_KEY_PAIR_GEN:
            {
                var key = SlhDsa.GenerateKey(MapSlhDsa((CkpSlhDsa)paramSet));
                StorePqc(CKK.CKK_SLH_DSA, paramSet, key.ExportSlhDsaPublicKey(), key, pub, priv, ref publicKey, ref privateKey);
                return CKR.CKR_OK;
            }
            case CKM.CKM_ML_KEM_KEY_PAIR_GEN:
            {
                var key = MLKem.GenerateKey(MapMlKem((CkpMlKem)paramSet));
                StorePqc(CKK.CKK_ML_KEM, paramSet, key.ExportEncapsulationKey(), key, pub, priv, ref publicKey, ref privateKey);
                return CKR.CKR_OK;
            }
            default:
                return CKR.CKR_MECHANISM_INVALID;
        }
    }

    private void StorePqc(CKK keyType, ulong paramSet, byte[] pubValue, object key,
        Dictionary<ulong, byte[]> pub, Dictionary<ulong, byte[]> priv,
        ref NativeCULong publicKey, ref NativeCULong privateKey)
    {
        SetCommon(pub, CKO.CKO_PUBLIC_KEY, keyType);
        SetCommon(priv, CKO.CKO_PRIVATE_KEY, keyType);
        pub[(ulong)CKA.CKA_PARAMETER_SET] = UlongAttr(paramSet);
        priv[(ulong)CKA.CKA_PARAMETER_SET] = UlongAttr(paramSet);
        pub[(ulong)CKA.CKA_VALUE] = pubValue; // FIPS public-key / encapsulation-key encoding
        Finish(key, pub, priv, ref publicKey, ref privateKey);
    }

    // === Sign (ML-DSA / SLH-DSA) =========================================

    private static bool IsPqcSign(CKM m) => m is CKM.CKM_ML_DSA or CKM.CKM_SLH_DSA;

    private static byte[] PqcSign(CKM m, object key, byte[] data, byte[] context) => m switch
    {
        CKM.CKM_ML_DSA => ((MLDsa)key).SignData(data, context),
        CKM.CKM_SLH_DSA => ((SlhDsa)key).SignData(data, context),
        _ => throw new CryptographicException($"ManagedSoftToken: unsupported PQC sign {m}."),
    };

    private static bool PqcVerify(CKM m, object key, byte[] data, byte[] sig, byte[] context) => m switch
    {
        CKM.CKM_ML_DSA => ((MLDsa)key).VerifyData(data, sig, context),
        CKM.CKM_SLH_DSA => ((SlhDsa)key).VerifyData(data, sig, context),
        _ => throw new CryptographicException($"ManagedSoftToken: unsupported PQC verify {m}."),
    };

    // === ML-KEM encapsulate / decapsulate ================================

    public override CKR C_EncapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey,
        CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong derivedKey)
    {
        if (!_sessions.Contains((ulong)session)) return CKR.CKR_SESSION_HANDLE_INVALID;
        if (!_asymKeys.TryGetValue((ulong)publicKey, out var k) || k is not MLKem kem) return CKR.CKR_KEY_HANDLE_INVALID;

        int ctSize = kem.Algorithm.CiphertextSizeInBytes;
        if (ciphertext is null || ciphertext.Length < ctSize)
        {
            ciphertextLen = (NativeCULong)(ulong)ctSize; // length probe
            return CKR.CKR_BUFFER_TOO_SMALL;
        }

        kem.Encapsulate(out byte[] ct, out byte[] sharedSecret);
        Array.Copy(ct, ciphertext, ct.Length);
        ciphertextLen = (NativeCULong)(ulong)ct.Length;
        derivedKey = (NativeCULong)StoreSharedSecret(template, attributeCount, sharedSecret);
        return CKR.CKR_OK;
    }

    public override CKR C_DecapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey,
        CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, NativeCULong ciphertextLen, ref NativeCULong derivedKey)
    {
        if (!_sessions.Contains((ulong)session)) return CKR.CKR_SESSION_HANDLE_INVALID;
        if (!_asymKeys.TryGetValue((ulong)privateKey, out var k) || k is not MLKem kem) return CKR.CKR_KEY_HANDLE_INVALID;

        byte[] ct = ciphertext.AsSpan(0, (int)ciphertextLen).ToArray();
        byte[] sharedSecret = kem.Decapsulate(ct);
        derivedKey = (NativeCULong)StoreSharedSecret(template, attributeCount, sharedSecret);
        return CKR.CKR_OK;
    }

    private ulong StoreSharedSecret(CK_ATTRIBUTE[] template, NativeCULong count, byte[] sharedSecret)
    {
        var attrs = ReadTemplate(template, count);
        attrs[(ulong)CKA.CKA_VALUE] = sharedSecret;
        attrs.TryAdd((ulong)CKA.CKA_CLASS, UlongAttr((ulong)CKO.CKO_SECRET_KEY));
        return Store(attrs);
    }

    // === Parameter-set maps ==============================================

    private static MLDsaAlgorithm MapMlDsa(CkpMlDsa p) => p switch
    {
        CkpMlDsa.CKP_ML_DSA_44 => MLDsaAlgorithm.MLDsa44,
        CkpMlDsa.CKP_ML_DSA_65 => MLDsaAlgorithm.MLDsa65,
        CkpMlDsa.CKP_ML_DSA_87 => MLDsaAlgorithm.MLDsa87,
        _ => throw new CryptographicException($"ManagedSoftToken: unsupported ML-DSA parameter set {p}."),
    };

    private static MLKemAlgorithm MapMlKem(CkpMlKem p) => p switch
    {
        CkpMlKem.CKP_ML_KEM_512 => MLKemAlgorithm.MLKem512,
        CkpMlKem.CKP_ML_KEM_768 => MLKemAlgorithm.MLKem768,
        CkpMlKem.CKP_ML_KEM_1024 => MLKemAlgorithm.MLKem1024,
        _ => throw new CryptographicException($"ManagedSoftToken: unsupported ML-KEM parameter set {p}."),
    };

    private static SlhDsaAlgorithm MapSlhDsa(CkpSlhDsa p) => p switch
    {
        CkpSlhDsa.CKP_SLH_DSA_SHA2_128S => SlhDsaAlgorithm.SlhDsaSha2_128s,
        CkpSlhDsa.CKP_SLH_DSA_SHA2_128F => SlhDsaAlgorithm.SlhDsaSha2_128f,
        CkpSlhDsa.CKP_SLH_DSA_SHA2_192S => SlhDsaAlgorithm.SlhDsaSha2_192s,
        CkpSlhDsa.CKP_SLH_DSA_SHA2_192F => SlhDsaAlgorithm.SlhDsaSha2_192f,
        CkpSlhDsa.CKP_SLH_DSA_SHA2_256S => SlhDsaAlgorithm.SlhDsaSha2_256s,
        CkpSlhDsa.CKP_SLH_DSA_SHA2_256F => SlhDsaAlgorithm.SlhDsaSha2_256f,
        CkpSlhDsa.CKP_SLH_DSA_SHAKE_128S => SlhDsaAlgorithm.SlhDsaShake128s,
        CkpSlhDsa.CKP_SLH_DSA_SHAKE_128F => SlhDsaAlgorithm.SlhDsaShake128f,
        CkpSlhDsa.CKP_SLH_DSA_SHAKE_192S => SlhDsaAlgorithm.SlhDsaShake192s,
        CkpSlhDsa.CKP_SLH_DSA_SHAKE_192F => SlhDsaAlgorithm.SlhDsaShake192f,
        CkpSlhDsa.CKP_SLH_DSA_SHAKE_256S => SlhDsaAlgorithm.SlhDsaShake256s,
        CkpSlhDsa.CKP_SLH_DSA_SHAKE_256F => SlhDsaAlgorithm.SlhDsaShake256f,
        _ => throw new CryptographicException($"ManagedSoftToken: unsupported SLH-DSA parameter set {p}."),
    };
}
