using System.Runtime.CompilerServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// Every mechanism-parameter wrapper carries a finalizer that frees its unmanaged buffers when the
/// caller forgets to <c>Dispose</c>. Those finalizers run only under GC, so their coverage is
/// otherwise incidental (and non-deterministic). This test constructs one of each — undisposed —
/// then forces a collection so every finalizer runs deterministically and the buffers are released.
/// </summary>
public sealed class MechanismParamsFinalizerTests
{
    [Fact]
    public void Finalizers_RunAndReleaseUnmanagedMemory_WhenNotDisposed()
    {
        WeakReference[] refs = CreateUndisposed();

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        // All wrappers were unreferenced after CreateUndisposed returned; a full collect must have
        // reclaimed them, which proves their finalizers ran (freeing the unmanaged buffers).
        Assert.All(refs, r => Assert.False(r.IsAlive));
    }

    // Kept out-of-line so the JIT cannot extend the wrappers' lifetime into the test method.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference[] CreateUndisposed()
    {
        object[] wrappers =
        [
            new CkmAesCcmParams(16, new byte[13], default, 16),
            new CkmAesGcmParams(new byte[12], default, 128),
            CkmCcmMessageParams.ForEncrypt(dataLen: 64, new byte[13], macBytes: 16),
            new CkmChaCha20Params(new byte[4], blockCounterBits: 32, new byte[12], nonceBits: 96),
            new CkmEcdh1DeriveParams(CKD.CKD_NULL, new byte[32]),
            new CkmEddsaParams(phFlag: false),
            CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16),
            new CkmHashPqcSignParams(CKM.CKM_SHA256, CkhHedge.CKH_HEDGE_REQUIRED, new byte[] { 0xAA }),
            new CkmHkdfParams(extract: true, expand: true, CKM.CKM_SHA256_HMAC, saltType: 1, new byte[4], saltKey: 0, new byte[3]),
            new CkmIke1ExtendedDeriveParams(CKM.CKM_SHA256_HMAC, hasKeygxy: true, keygxy: 5, new byte[2]),
            new CkmIke1PrfDeriveParams(CKM.CKM_SHA256_HMAC, hasPrevKey: true, keygxy: 1, prevKey: 2, new byte[2], new byte[1], keyNumber: 9),
            new CkmIke2PrfPlusDeriveParams(CKM.CKM_SHA256_HMAC, hasSeedKey: false, seedKey: 0, new byte[3]),
            new CkmIkePrfDeriveParams(CKM.CKM_SHA256_HMAC, dataAsKey: true, rekey: false, new byte[3], new byte[2], newKey: 7),
            new CkmPqcSignParams(CkhHedge.CKH_HEDGE_REQUIRED, new byte[] { 1, 2, 3 }),
            new CkmRc2CbcParams(128, new byte[8]),
            new CkmRc2Params(64),
            new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256),
            new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, saltLength: 32),
            CkmSalsa20ChaCha20Poly1305MsgParams.ForEncrypt(new byte[12]),
            new CkmSalsa20ChaCha20Poly1305Params(new byte[12], new byte[2]),
            new CkmSalsa20Params(new byte[8], new byte[8], nonceBits: 64),
            CkmSp800108KdfParams.CounterModeHmac(CKM.CKM_SHA256_HMAC, new byte[2], new byte[2]),
            CkmSp800108KdfParams.Feedback(CKM.CKM_SHA256_HMAC).IterationCounter().ByteArray([1]).DkmLength(Sp800108DkmLengthMethod.SumOfKeys).WithIV(new byte[8]).Build(),
            CkmSp800108KdfParams.DoublePipeline(CKM.CKM_SHA256_HMAC).IterationCounter().ByteArray([1]).DkmLength(Sp800108DkmLengthMethod.SumOfKeys).Build(),
            new CkmX2RatchetInitializeParams(new byte[8], peerPublicPrekey: 1, peerPublicIdentity: 2, ownPublicIdentity: 3, encryptedHeader: true, curve: 4, CKM.CKM_AES_GCM, kdfMechanism: 5),
            new CkmX2RatchetRespondParams(new byte[4], ownPrekey: 1, initiatorIdentity: 2, ownPublicIdentity: 3, encryptedHeader: false, curve: 4, CKM.CKM_AES_GCM, kdfMechanism: 6),
            new CkmX3dhInitiateParams(kdf: 1, peerIdentity: 2, peerPrekey: 3, new byte[3], new byte[2], ownIdentity: 4, ownEphemeral: 5),
            new CkmX3dhRespondParams(kdf: 7, new byte[1], new byte[2], new byte[1], initiatorIdentity: 8, new byte[3]),
            new CkmXeddsaParams(hashType: (ulong)CKM.CKM_SHA512),
        ];

        var refs = new WeakReference[wrappers.Length];
        for (int i = 0; i < wrappers.Length; i++)
            refs[i] = new WeakReference(wrappers[i]);
        return refs;
    }
}
