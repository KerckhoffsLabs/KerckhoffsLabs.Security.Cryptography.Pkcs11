using System.Reflection;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// Census over every mechanism-parameter wrapper, asserting none of them declares a finalizer or owns
/// unmanaged memory. This replaces the old census, which asserted that the finalizers ran: they
/// existed to release buffers the constructors allocated, and both are gone — the per-call scope owns
/// everything now.
/// </summary>
/// <remarks>
/// Joins the serialized MemoryLeaks collection because
/// <see cref="ConstructingParameters_AllocatesNoUnmanagedMemory"/> asserts an exact
/// <see cref="UnmanagedMemory.OutstandingAllocationCount"/>, which is process-wide: a concurrent
/// test holding an allocation across the window would make the count differ on a correct build.
/// Every other class that reads that counter is in this collection for the same reason.
/// </remarks>
[Collection("MemoryLeaks")]
public sealed class MechanismParamsFinalizerTests
{
    /// <summary>
    /// Every concrete <see cref="MechanismParameters"/> subclass, found by reflection rather than
    /// listed, so a newly added type is covered without anyone remembering to add it.
    /// </summary>
    private static Type[] ConcreteParameterTypes =>
        [.. typeof(MechanismParameters).Assembly
            .GetTypes()
            .Where(t => !t.IsAbstract && typeof(MechanismParameters).IsAssignableFrom(t))
            .OrderBy(t => t.Name, StringComparer.Ordinal)];

    /// <summary>
    /// No parameter type declares a finalizer. Each one existed solely to free a constructor-allocated
    /// buffer, so a type that regains one is either leaking managed-only work onto the finalizer queue
    /// or has quietly started owning unmanaged memory again.
    /// </summary>
    /// <remarks>
    /// This is the assertion the sibling allocation census cannot make: a finalizer with nothing to
    /// free allocates nothing, so it would pass there unnoticed.
    /// </remarks>
    [Fact]
    public void NoParameterType_DeclaresAFinalizer()
    {
        Type[] all = ConcreteParameterTypes;

        // Guard against a reflection filter that silently matches nothing and passes vacuously.
        Assert.Contains(nameof(CkmAesGcmParams), all.Select(t => t.Name));
        Assert.True(all.Length >= 27, $"expected the full parameter surface, found {all.Length}");

        string[] withFinalizers =
            [.. all.Where(static t => t.GetMethod(
                    "Finalize",
                    BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly) is not null)
                .Select(static t => t.Name)];

        Assert.Empty(withFinalizers);
    }

    /// <summary>
    /// No parameter type owns unmanaged memory any more, so constructing one must not allocate.
    /// </summary>
    [Fact]
    public void ConstructingParameters_AllocatesNoUnmanagedMemory()
    {
        // The keys the key-valued types reference are built first: only the parameters are under test.
        using var keys = new ParameterKeys();
        Pkcs11Key secret = keys.Secret(1), pair = keys.Pair(2, 3);
        int before = UnmanagedMemory.OutstandingAllocationCount;

        object[] wrappers = CreateOneOfEach(secret, pair);

        Assert.Equal(before, UnmanagedMemory.OutstandingAllocationCount);
        Assert.NotEmpty(wrappers);
    }

    private static object[] CreateOneOfEach(Pkcs11Key secret, Pkcs11Key pair) =>
    [
        new CkmAesCcmParams(16, new byte[13], default, 16),
        new CkmAesGcmParams(new byte[12], default, 128),
        CkmCcmMessageParams.ForEncrypt(dataLen: 64, new byte[13], macBytes: 16),
        new CkmChaCha20Params(new byte[4], blockCounterBits: 32, new byte[12], nonceBits: 96),
        new CkmEcdh1DeriveParams(CKD.CKD_NULL, new byte[32]),
        new CkmEddsaParams(phFlag: false),
        CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16),
        new CkmHashPqcSignParams(CKM.CKM_SHA256, CkhHedge.CKH_HEDGE_REQUIRED, [0xAA]),
        CkmHkdfParams.WithSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256_HMAC, new byte[4], new byte[3]),
        new CkmIke1ExtendedDeriveParams(CKM.CKM_SHA256_HMAC, keygxy: secret, new byte[2]),
        new CkmIke1PrfDeriveParams(CKM.CKM_SHA256_HMAC, keygxy: secret, prevKey: secret, new byte[2], new byte[1], keyNumber: 9),
        new CkmIke2PrfPlusDeriveParams(CKM.CKM_SHA256_HMAC, seedKey: null, new byte[3]),
        new CkmIkePrfDeriveParams(CKM.CKM_SHA256_HMAC, dataAsKey: true, rekey: false, new byte[3], new byte[2], newKey: secret),
        new CkmPqcSignParams(CkhHedge.CKH_HEDGE_REQUIRED, [1, 2, 3]),
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
        new CkmX2RatchetInitializeParams(new byte[8], peerPublicPrekey: pair, peerPublicIdentity: pair, ownPublicIdentity: pair, encryptedHeader: true, curve: 4, CKM.CKM_AES_GCM, kdfMechanism: CKM.CKM_SHA256_HMAC),
        new CkmX2RatchetRespondParams(new byte[4], ownPrekey: pair, initiatorIdentity: pair, ownPublicIdentity: pair, encryptedHeader: false, curve: 4, CKM.CKM_AES_GCM, kdfMechanism: CKM.CKM_SHA384_HMAC),
        new CkmX3dhInitiateParams(kdf: CKM.CKM_SHA256_HMAC, peerIdentity: pair, peerPrekey: pair, new byte[3], new byte[2], ownIdentity: pair, ownEphemeral: pair),
        new CkmX3dhRespondParams(kdf: CKM.CKM_SHA384_HMAC, new byte[1], new byte[2], new byte[1], initiatorIdentity: pair, new byte[3]),
        new CkmXeddsaParams(CKM.CKM_SHA512),
    ];
}
