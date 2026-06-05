using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

/// <summary>
/// An in-process PKCS#11 token implemented in managed code, backed by the BCL
/// <c>System.Security.Cryptography</c> primitives. It exercises the <c>Algorithms</c> adapters
/// end-to-end without SoftHSM via an in-memory object store and per-family mechanism dispatchers.
/// This core file holds the object/session model plus symmetric AES; sibling partials add the
/// other families (<c>ManagedSoftToken.Digest.cs</c>, <c>ManagedSoftToken.Hmac.cs</c>, …).
/// </summary>
internal sealed partial class ManagedSoftToken : NotSupportedPkcs11Library
{
    public const string TokenLabel = "managed-soft-token";
    private const ulong SlotId = 0;

    private ulong _nextHandle = 100;
    private ulong _nextSession = 1;
    private readonly Dictionary<ulong, Dictionary<ulong, byte[]>> _objects = [];
    private readonly HashSet<ulong> _sessions = [];
    private readonly Dictionary<ulong, Queue<ulong>> _finds = [];

    // PKCS#11 "attribute unavailable" sentinel: (CK_ULONG)-1, all-ones at the platform's CK_ULONG
    // width (4 bytes on Windows, 8 on Linux-LP64). NativeCULong.MaxValue is exactly that on both —
    // building it from nuint.MaxValue overflows the checked narrowing on Windows.
    private static readonly NativeCULong AttrUnavailable = NativeCULong.MaxValue;

    // === Lifecycle / discovery ===========================================

    public override CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs) => CKR.CKR_OK;
    public override CKR C_Finalize(IntPtr reserved) => CKR.CKR_OK;

    public override CKR C_GetSlotList(bool tokenPresent, NativeCULong[]? slotList, ref NativeCULong count)
    {
        if (slotList is null) { count = (NativeCULong)1; return CKR.CKR_OK; }
        if ((int)count < 1) { count = (NativeCULong)1; return CKR.CKR_BUFFER_TOO_SMALL; }
        slotList[0] = (NativeCULong)SlotId;
        count = (NativeCULong)1;
        return CKR.CKR_OK;
    }

    public override CKR C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info) => CKR.CKR_OK;

    public override CKR C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info)
    {
        NativeTestStructs.FillPadded(info.Label, TokenLabel);
        return CKR.CKR_OK;
    }

    public override CKR C_GetMechanismList(NativeCULong slotId, CKM[]? mechanismList, ref NativeCULong count)
    {
        CKM[] mechs =
        [
            CKM.CKM_AES_KEY_GEN, CKM.CKM_AES_CBC, CKM.CKM_AES_CBC_PAD, CKM.CKM_AES_ECB,
            CKM.CKM_GENERIC_SECRET_KEY_GEN,
            CKM.CKM_SHA256, CKM.CKM_SHA384, CKM.CKM_SHA512,
            CKM.CKM_SHA3_256, CKM.CKM_SHA3_384, CKM.CKM_SHA3_512,
            CKM.CKM_SHA256_HMAC, CKM.CKM_SHA384_HMAC, CKM.CKM_SHA512_HMAC,
        ];
        if (mechanismList is null) { count = (NativeCULong)mechs.Length; return CKR.CKR_OK; }
        if ((int)count < mechs.Length) { count = (NativeCULong)mechs.Length; return CKR.CKR_BUFFER_TOO_SMALL; }
        Array.Copy(mechs, mechanismList, mechs.Length);
        count = (NativeCULong)mechs.Length;
        return CKR.CKR_OK;
    }

    public override CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session)
    {
        ulong id = _nextSession++;
        _sessions.Add(id);
        session = (NativeCULong)id;
        return CKR.CKR_OK;
    }

    public override CKR C_CloseSession(NativeCULong session)
    {
        ulong s = (ulong)session;
        _sessions.Remove(s);
        _ops.Remove(s);
        _finds.Remove(s);
        return CKR.CKR_OK;
    }

    public override CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
    {
        info.SlotId = (NativeCULong)SlotId;
        return CKR.CKR_OK;
    }

    public override CKR C_Login(NativeCULong session, CKU userType, byte[] pin, NativeCULong pinLen) => CKR.CKR_OK;

    /// <summary>Number of times <c>C_Logout</c> has been invoked. Used to assert logout-on-dispose.</summary>
    public int LogoutCallCount { get; private set; }

    /// <summary>Return value the next <c>C_Logout</c> should report. Lets tests exercise the
    /// best-effort swallow path (e.g. <see cref="CKR.CKR_USER_NOT_LOGGED_IN"/>).</summary>
    public CKR LogoutResult { get; set; } = CKR.CKR_OK;

    public override CKR C_Logout(NativeCULong session)
    {
        LogoutCallCount++;
        return LogoutResult;
    }

    // === Objects =========================================================

    public override CKR C_GenerateKey(NativeCULong session, ref CK_MECHANISM mechanism, CK_ATTRIBUTE[]? template, NativeCULong count, ref NativeCULong key)
    {
        if (!_sessions.Contains((ulong)session)) return CKR.CKR_SESSION_HANDLE_INVALID;
        var keyGen = (CKM)(ulong)mechanism.Mechanism;
        if (keyGen is not (CKM.CKM_AES_KEY_GEN or CKM.CKM_GENERIC_SECRET_KEY_GEN))
            return CKR.CKR_MECHANISM_INVALID;

        var attrs = ReadTemplate(template, count);
        if (!attrs.TryGetValue((ulong)CKA.CKA_VALUE_LEN, out var vl)) return CKR.CKR_TEMPLATE_INCOMPLETE;
        int len = (int)ToUlong(vl);
        if (len <= 0 || (keyGen == CKM.CKM_AES_KEY_GEN && len is not (16 or 24 or 32)))
            return CKR.CKR_ATTRIBUTE_VALUE_INVALID;

        attrs[(ulong)CKA.CKA_VALUE] = RandomNumberGenerator.GetBytes(len);
        key = (NativeCULong)Store(attrs);
        return CKR.CKR_OK;
    }

    public override CKR C_CreateObject(NativeCULong session, CK_ATTRIBUTE[]? template, NativeCULong count, ref NativeCULong objectId)
    {
        var attrs = ReadTemplate(template, count);
        ulong handle = Store(attrs);
        RegisterImportedAsymKey(handle, attrs); // reconstructs a live BCL DSA for CKK_DSA imports
        objectId = (NativeCULong)handle;
        return CKR.CKR_OK;
    }

    /// <summary>When set, the next <c>C_DestroyObject</c> reports this code and leaves the object
    /// in place — lets tests exercise the path where a token rejects the destroy.</summary>
    public CKR? DestroyObjectResultOverride { get; set; }

    public override CKR C_DestroyObject(NativeCULong session, NativeCULong objectId)
    {
        if (DestroyObjectResultOverride is { } forced)
            return forced;
        return _objects.Remove((ulong)objectId) ? CKR.CKR_OK : CKR.CKR_OBJECT_HANDLE_INVALID;
    }

    public override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, NativeCULong count)
    {
        if (!_objects.TryGetValue((ulong)objectId, out var obj)) return CKR.CKR_OBJECT_HANDLE_INVALID;

        CKR rv = CKR.CKR_OK;
        int n = (int)count;
        for (int i = 0; i < n; i++)
        {
            ulong type = (ulong)template[i].type;
            if (!obj.TryGetValue(type, out var val))
            {
                // PKCS#11 sentinel: ulValueLen = (CK_ULONG)-1 marks an unavailable attribute.
                template[i].valueLen = AttrUnavailable;
                rv = CKR.CKR_ATTRIBUTE_TYPE_INVALID; // non-fatal in the caller's two-pass read
                continue;
            }

            // Pass 1 (value == NULL): report the size. Pass 2: copy into the caller's buffer.
            if (template[i].value != IntPtr.Zero)
                UnmanagedMemory.Write(template[i].value, val);
            template[i].valueLen = (NativeCULong)(ulong)val.Length;
        }
        return rv;
    }

    // === Find ============================================================

    public override CKR C_FindObjectsInit(NativeCULong session, CK_ATTRIBUTE[]? template, NativeCULong count)
    {
        var filter = ReadTemplate(template, count);
        var matches = _objects
            .Where(kv => filter.All(f => kv.Value.TryGetValue(f.Key, out var v) && v.AsSpan().SequenceEqual(f.Value)))
            .Select(kv => kv.Key);
        _finds[(ulong)session] = new Queue<ulong>(matches);
        return CKR.CKR_OK;
    }

    public override CKR C_FindObjects(NativeCULong session, NativeCULong[] objectId, NativeCULong maxObjectCount, ref NativeCULong objectCount)
    {
        if (!_finds.TryGetValue((ulong)session, out var q)) { objectCount = (NativeCULong)0; return CKR.CKR_OK; }
        int max = (int)maxObjectCount, i = 0;
        while (i < max && q.Count > 0) objectId[i++] = (NativeCULong)q.Dequeue();
        objectCount = (NativeCULong)(ulong)i;
        return CKR.CKR_OK;
    }

    public override CKR C_FindObjectsFinal(NativeCULong session)
    {
        _finds.Remove((ulong)session);
        return CKR.CKR_OK;
    }

    // === Random ==========================================================

    public override CKR C_GenerateRandom(NativeCULong session, byte[] randomData, NativeCULong randomLen)
    {
        RandomNumberGenerator.Fill(randomData.AsSpan(0, (int)randomLen));
        return CKR.CKR_OK;
    }

    // (Symmetric encrypt/decrypt — block ciphers + AEAD — lives in ManagedSoftToken.Symmetric.cs.)

    // === Helpers =========================================================

    private ulong Store(Dictionary<ulong, byte[]> attrs)
    {
        ulong handle = _nextHandle++;
        _objects[handle] = attrs;
        return handle;
    }

    private static Dictionary<ulong, byte[]> ReadTemplate(CK_ATTRIBUTE[]? template, NativeCULong count)
    {
        var dict = new Dictionary<ulong, byte[]>();
        if (template is null) return dict;
        int n = (int)count;
        for (int i = 0; i < n; i++)
        {
            ulong type = (ulong)template[i].type;
            byte[] val = template[i].value != IntPtr.Zero && (int)template[i].valueLen > 0
                ? UnmanagedMemory.Read(template[i].value, (int)template[i].valueLen)
                : [];
            dict[type] = val;
        }
        return dict;
    }

    private static ulong ToUlong(byte[] b) => b.Length switch
    {
        8 => BitConverter.ToUInt64(b),
        4 => BitConverter.ToUInt32(b),
        1 => b[0],
        _ => 0,
    };
}
