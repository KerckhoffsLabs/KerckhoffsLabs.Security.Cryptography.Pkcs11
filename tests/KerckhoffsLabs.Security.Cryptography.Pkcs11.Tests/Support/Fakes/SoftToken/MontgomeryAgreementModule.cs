using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

/// <summary>
/// A <see cref="FakeModule"/> holding one <see cref="CKK.CKK_EC_MONTGOMERY"/> private key (handle 1) whose
/// <c>CKA_EC_PARAMS</c> is <c>ecParams</c>, and whose <c>C_DeriveKey</c> answers every derivation with a
/// generic secret (handle 3) holding <c>secret</c>, whatever the peer: a token that checks nothing. It records
/// what the derivation was given, so a test can see the exact <c>CK_ECDH1_DERIVE_PARAMS</c> and template the
/// library sent. The .NET BCL has no X25519 or X448, and the <see cref="ManagedSoftToken"/> no Montgomery
/// keys, so this is how a unit test drives <c>Pkcs11Key.DeriveRawSecret</c> and
/// <c>Pkcs11Key.DeriveSecretAgreement</c> on such a key. <c>deriveResult</c> other than <c>CKR_OK</c> makes
/// <c>C_DeriveKey</c> fail with it, after recording what it was given.
/// </summary>
internal sealed class MontgomeryAgreementModule(byte[] ecParams, byte[] secret, CKR deriveResult = CKR.CKR_OK) : FakeModule
{
    private const ulong PrivateKey = 1;
    private const ulong Derived = 3;

    protected override bool ReleasedByFinalize => true;

    /// <summary>The mechanism of the last <c>C_DeriveKey</c>, or <see langword="null"/> before one.</summary>
    public CKM? DerivedWith { get; private set; }

    /// <summary>The KDF of the last derivation's <c>CK_ECDH1_DERIVE_PARAMS</c>.</summary>
    public CKD? Kdf { get; private set; }

    /// <summary>The peer public data of the last derivation's <c>CK_ECDH1_DERIVE_PARAMS</c>.</summary>
    public byte[]? PublicData { get; private set; }

    /// <summary>The <c>CKA_VALUE_LEN</c> of the last derivation's template, or <see langword="null"/> without one.</summary>
    public ulong? ValueLen { get; private set; }

    /// <summary>The handles <c>C_DestroyObject</c> was called for.</summary>
    public List<ulong> Destroyed { get; } = [];

    /// <summary>How many times <c>C_GetAttributeValue</c> was asked for the private key's <c>CKA_EC_PARAMS</c>.</summary>
    public int EcParamsReads { get; private set; }

    /// <summary>The template of the last <c>C_DeriveKey</c>, as (type, value) pairs.</summary>
    public List<(CKA Type, byte[] Value)> DeriveTemplate { get; } = [];

    /// <summary>Builds a session over this module and the Montgomery private key in it.</summary>
    public FakeKey CreateKey(ICryptoPolicy policy, ILoggerFactory? loggerFactory = null)
    {
        var library = Load();
        var lowLevel = library.LowLevelLibrary!;
        var slot = new Pkcs11Slot(library, slotId: 1);
        var core = new Pkcs11SessionCore(lowLevel, slotId: default, sessionId: 1, loggerFactory: loggerFactory, policy: policy);
        var session = new Pkcs11Session(library, slot, core);
        var key = new Pkcs11Key(
            session,
            privateHandle: new ObjectHandle(PrivateKey),
            publicHandle: ObjectHandle.Invalid,
            keyType: CKK.CKK_EC_MONTGOMERY,
            label: null,
            id: []);
        return new FakeKey(key, session, library);
    }

    protected override CKR C_DeriveKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[] template, ref NativeCULong key)
    {
        if ((ulong)baseKey != PrivateKey)
            return CKR.CKR_KEY_HANDLE_INVALID;

        DerivedWith = (CKM)(ulong)mechanism.Mechanism;
        if (mechanism.Parameter != IntPtr.Zero)
        {
            var p = UnmanagedMemory.Read<CK_ECDH1_DERIVE_PARAMS>(mechanism.Parameter);
            Kdf = (CKD)(ulong)p.Kdf;
            PublicData = UnmanagedMemory.Read(p.PublicData, (int)p.PublicDataLen);
        }
        ValueLen = null;
        foreach (CK_ATTRIBUTE attribute in template.Where(a => (CKA)(ulong)a.type == CKA.CKA_VALUE_LEN))
            ValueLen = (ulong)UnmanagedMemory.Read<NativeCULong>(attribute.value);
        DeriveTemplate.Clear();
        foreach (CK_ATTRIBUTE attribute in template)
            DeriveTemplate.Add(((CKA)(ulong)attribute.type, UnmanagedMemory.Read(attribute.value, (int)(ulong)attribute.valueLen)));

        if (deriveResult != CKR.CKR_OK)
            return deriveResult;
        key = (NativeCULong)Derived;
        return CKR.CKR_OK;
    }

    protected override CKR C_DestroyObject(NativeCULong session, NativeCULong objectId)
    {
        Destroyed.Add((ulong)objectId);
        return CKR.CKR_OK;
    }

    protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template)
    {
        CKR result = CKR.CKR_OK;
        for (int i = 0; i < template.Length; i++)
        {
            if ((ulong)objectId == PrivateKey && (CKA)(ulong)template[i].type == CKA.CKA_EC_PARAMS && template[i].value != IntPtr.Zero)
                EcParamsReads++;
            byte[]? value = Value((ulong)objectId, (CKA)(ulong)template[i].type);
            if (value is null)
            {
                template[i].valueLen = NativeCULong.MaxValue;
                result = CKR.CKR_ATTRIBUTE_TYPE_INVALID;
                continue;
            }

            if (template[i].value != IntPtr.Zero)
            {
                if ((ulong)template[i].valueLen < (ulong)value.Length)
                {
                    template[i].valueLen = NativeCULong.MaxValue;
                    result = CKR.CKR_BUFFER_TOO_SMALL;
                    continue;
                }
                UnmanagedMemory.Write(template[i].value, value);
            }
            template[i].valueLen = (NativeCULong)(ulong)value.Length;
        }
        return result;
    }

    private byte[]? Value(ulong handle, CKA type) => (handle, type) switch
    {
        (PrivateKey, CKA.CKA_CLASS) => Ulong((ulong)CKO.CKO_PRIVATE_KEY),
        (PrivateKey, CKA.CKA_KEY_TYPE) => Ulong((ulong)CKK.CKK_EC_MONTGOMERY),
        (PrivateKey, CKA.CKA_EC_PARAMS) => ecParams,
        (Derived, CKA.CKA_CLASS) => Ulong((ulong)CKO.CKO_SECRET_KEY),
        (Derived, CKA.CKA_KEY_TYPE) => Ulong((ulong)CKK.CKK_GENERIC_SECRET),
        (Derived, CKA.CKA_VALUE) => secret,
        (_, CKA.CKA_LABEL or CKA.CKA_ID) => [],
        _ => null,
    };

    private static byte[] Ulong(ulong value) => BitConverter.GetBytes(value).AsSpan(0, UnmanagedMemory.NativeULongSize).ToArray();
}
