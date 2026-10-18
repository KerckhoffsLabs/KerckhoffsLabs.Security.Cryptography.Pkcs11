using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

/// <summary>
/// A module that checks every pointer the library builds into a structure against the library's own
/// allocations: each attribute value (nested templates included), each mechanism parameter block, and the
/// buffers that block points to. Each must lie in a live <see cref="UnmanagedMemory"/> block, its whole
/// stated length inside that block. A pointer past its block's end, or into a block already freed, is
/// recorded in <see cref="Violations"/>, so the test fails with a message rather than a corrupted heap.
/// </summary>
/// <remarks>
/// <para>
/// Guard pages (<c>GuardedMemory</c>) catch this for memory a caller lends, but cannot reach
/// memory the library allocates for itself; AddressSanitizer would, but it does not see the reads of a
/// managed module. The library allocates all of it through <see cref="UnmanagedMemory"/>, which tracks
/// every live block, so the check is exact.
/// </para>
/// <para>
/// Every function succeeds. <c>C_GetAttributeValue</c> answers each length query with
/// <see cref="AttributeValueLength"/> and fills each value it is then lent; <c>C_Encrypt</c> copies its
/// input.
/// </para>
/// </remarks>
internal sealed unsafe class AllocationBoundsModule : SessionTestModule
{
    public const int AttributeValueLength = 5;

    private static readonly int AttributeSize = UnmanagedMemory.SizeOf<CK_ATTRIBUTE>();

    /// <summary>Each pointer that was not inside a live block of its stated length, described.</summary>
    public List<string> Violations { get; } = [];

    /// <summary>What was checked and found inside its block, by description.</summary>
    public List<string> Checked { get; } = [];

    /// <summary>Checks that <paramref name="length"/> bytes at <paramref name="address"/> lie in one live block.</summary>
    /// <returns>Whether they do, so a caller may go on to read them.</returns>
    private bool Lent(IntPtr address, ulong length, string what)
    {
        if (length == 0)
            return false;
        if (address == IntPtr.Zero)
        {
            Violations.Add($"{what}: NULL with length {length}");
            return false;
        }
        if (!UnmanagedMemory.TryFindAllocation(address, out IntPtr start, out int size))
        {
            Violations.Add($"{what}: 0x{address:X} is in no live block (freed, or not allocated by the library)");
            return false;
        }

        ulong offset = (ulong)(address - start);
        if (offset + length > (ulong)size)
        {
            Violations.Add($"{what}: {length} bytes at offset {offset} of a {size}-byte block");
            return false;
        }

        Checked.Add(what);
        return true;
    }

    private void Template(ReadOnlySpan<CK_ATTRIBUTE> template, string what)
    {
        for (int i = 0; i < template.Length; i++)
        {
            CK_ATTRIBUTE attribute = template[i];
            var type = (CKA)(ulong)attribute.type;
            string name = $"{what}[{i}] {type}";
            // Of the array attributes, these hold CK_ATTRIBUTEs; CKA_ALLOWED_MECHANISMS holds mechanism types.
            bool holdsTemplate = type is CKA.CKA_WRAP_TEMPLATE or CKA.CKA_UNWRAP_TEMPLATE or CKA.CKA_DERIVE_TEMPLATE;
            if (!Lent(attribute.value, (ulong)attribute.valueLen, name) || !holdsTemplate)
                continue;

            ulong length = (ulong)attribute.valueLen;
            if (length % (ulong)AttributeSize != 0)
            {
                Violations.Add($"{name}: a {length}-byte value is not a whole number of CK_ATTRIBUTEs");
                continue;
            }

            var nested = new CK_ATTRIBUTE[(int)(length / (ulong)AttributeSize)];
            for (int j = 0; j < nested.Length; j++)
                nested[j] = UnmanagedMemory.Read<CK_ATTRIBUTE>(attribute.value + j * AttributeSize);
            Template(nested, name);
        }
    }

    private void Mechanism(CK_MECHANISM mechanism)
    {
        ulong length = (ulong)mechanism.ParameterLen;
        if (!Lent(mechanism.Parameter, length, "mechanism parameter"))
            return;

        IntPtr p = mechanism.Parameter;
        switch ((CKM)(ulong)mechanism.Mechanism)
        {
            case CKM.CKM_AES_GCM when Fits<CK_GCM_PARAMS>(length):
                var gcm = UnmanagedMemory.Read<CK_GCM_PARAMS>(p);
                Lent(gcm.Iv, (ulong)gcm.IvLen, "CK_GCM_PARAMS.pIv");
                Lent(gcm.AAD, (ulong)gcm.AADLen, "CK_GCM_PARAMS.pAAD");
                break;
            case CKM.CKM_AES_CCM when Fits<CK_CCM_PARAMS>(length):
                var ccm = UnmanagedMemory.Read<CK_CCM_PARAMS>(p);
                Lent(ccm.Nonce, (ulong)ccm.NonceLen, "CK_CCM_PARAMS.pNonce");
                Lent(ccm.AAD, (ulong)ccm.AADLen, "CK_CCM_PARAMS.pAAD");
                break;
            case CKM.CKM_RSA_PKCS_OAEP when Fits<CK_RSA_PKCS_OAEP_PARAMS>(length):
                var oaep = UnmanagedMemory.Read<CK_RSA_PKCS_OAEP_PARAMS>(p);
                Lent(oaep.SourceData, (ulong)oaep.SourceDataLen, "CK_RSA_PKCS_OAEP_PARAMS.pSourceData");
                break;
            case CKM.CKM_ECDH1_DERIVE or CKM.CKM_ECDH1_COFACTOR_DERIVE when Fits<CK_ECDH1_DERIVE_PARAMS>(length):
                var ecdh = UnmanagedMemory.Read<CK_ECDH1_DERIVE_PARAMS>(p);
                Lent(ecdh.SharedData, (ulong)ecdh.SharedDataLen, "CK_ECDH1_DERIVE_PARAMS.pSharedData");
                Lent(ecdh.PublicData, (ulong)ecdh.PublicDataLen, "CK_ECDH1_DERIVE_PARAMS.pPublicData");
                break;
            case CKM.CKM_PKCS5_PBKD2 when length == (ulong)UnmanagedMemory.SizeOf<CK_PKCS5_PBKD2_PARAMS2>():
                var pbkd2 = UnmanagedMemory.Read<CK_PKCS5_PBKD2_PARAMS2>(p);
                Lent(pbkd2.SaltSourceData, (ulong)pbkd2.SaltSourceDataLen, "CK_PKCS5_PBKD2_PARAMS2.pSaltSourceData");
                Lent(pbkd2.PrfData, (ulong)pbkd2.PrfDataLen, "CK_PKCS5_PBKD2_PARAMS2.pPrfData");
                Lent(pbkd2.Password, (ulong)pbkd2.PasswordLen, "CK_PKCS5_PBKD2_PARAMS2.pPassword");
                break;
            case CKM.CKM_PKCS5_PBKD2 when Fits<CK_PKCS5_PBKD2_PARAMS>(length):
                // The v2.40 layout: ulPasswordLen is a pointer to the length.
                var legacy = UnmanagedMemory.Read<CK_PKCS5_PBKD2_PARAMS>(p);
                Lent(legacy.SaltSourceData, (ulong)legacy.SaltSourceDataLen, "CK_PKCS5_PBKD2_PARAMS.pSaltSourceData");
                Lent(legacy.PrfData, (ulong)legacy.PrfDataLen, "CK_PKCS5_PBKD2_PARAMS.pPrfData");
                if (Lent(legacy.PasswordLen, (ulong)UnmanagedMemory.NativeULongSize, "CK_PKCS5_PBKD2_PARAMS.ulPasswordLen"))
                    Lent(legacy.Password, (ulong)UnmanagedMemory.Read<NativeCULong>(legacy.PasswordLen), "CK_PKCS5_PBKD2_PARAMS.pPassword");
                break;
            case CKM.CKM_HKDF_DERIVE or CKM.CKM_HKDF_DATA when Fits<CK_HKDF_PARAMS>(length):
                var hkdf = UnmanagedMemory.Read<CK_HKDF_PARAMS>(p);
                Lent(hkdf.Salt, (ulong)hkdf.SaltLen, "CK_HKDF_PARAMS.pSalt");
                Lent(hkdf.Info, (ulong)hkdf.InfoLen, "CK_HKDF_PARAMS.pInfo");
                break;
        }
    }

    private bool Fits<T>(ulong length) where T : unmanaged
    {
        if (length >= (ulong)UnmanagedMemory.SizeOf<T>())
            return true;
        Violations.Add($"mechanism parameter: {length} bytes, shorter than {typeof(T).Name}");
        return false;
    }

    private NativeCULong _nextObject = (NativeCULong)100;

    private NativeCULong NewObject() => _nextObject = (NativeCULong)((ulong)_nextObject + 1);

    protected override CKR C_CreateObject(NativeCULong session, CK_ATTRIBUTE[] template, ref NativeCULong objectId)
    {
        Template(template, "C_CreateObject template");
        objectId = NewObject();
        return CKR.CKR_OK;
    }

    protected override CKR C_CopyObject(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, ref NativeCULong newObjectId)
    {
        Template(template, "C_CopyObject template");
        newObjectId = NewObject();
        return CKR.CKR_OK;
    }

    protected override CKR C_SetAttributeValue(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template)
    {
        Template(template, "C_SetAttributeValue template");
        return CKR.CKR_OK;
    }

    protected override CKR C_FindObjectsInit(NativeCULong session, CK_ATTRIBUTE[] template)
    {
        Template(template, "C_FindObjectsInit template");
        return CKR.CKR_OK;
    }

    protected override CKR C_FindObjects(NativeCULong session, Span<NativeCULong> objects, ref NativeCULong count)
    {
        count = default;
        return CKR.CKR_OK;
    }

    protected override CKR C_FindObjectsFinal(NativeCULong session) => CKR.CKR_OK;

    protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
    {
        for (int i = 0; i < template.Length; i++)
        {
            ref CK_ATTRIBUTE attribute = ref template[i];
            if (attribute.value == IntPtr.Zero)
            {
                attribute.valueLen = (NativeCULong)AttributeValueLength;
                continue;
            }
            if (Lent(attribute.value, (ulong)attribute.valueLen, $"C_GetAttributeValue value[{i}] {(CKA)(ulong)attribute.type}"))
                new Span<byte>((void*)attribute.value, checked((int)(ulong)attribute.valueLen)).Fill(0x5A);
        }
        return CKR.CKR_OK;
    }

    protected override CKR C_GenerateKey(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, ref NativeCULong key)
    {
        Mechanism(mechanism);
        Template(template, "C_GenerateKey template");
        key = NewObject();
        return CKR.CKR_OK;
    }

    protected override CKR C_GenerateKeyPair(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicKeyTemplate, CK_ATTRIBUTE[] privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey)
    {
        Mechanism(mechanism);
        Template(publicKeyTemplate, "C_GenerateKeyPair public template");
        Template(privateKeyTemplate, "C_GenerateKeyPair private template");
        publicKey = NewObject();
        privateKey = NewObject();
        return CKR.CKR_OK;
    }

    protected override CKR C_DeriveKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[] template, ref NativeCULong key)
    {
        Mechanism(mechanism);
        Template(template, "C_DeriveKey template");
        key = NewObject();
        return CKR.CKR_OK;
    }

    protected override CKR C_UnwrapKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey, CK_ATTRIBUTE[] template, ref NativeCULong key)
    {
        Mechanism(mechanism);
        Template(template, "C_UnwrapKey template");
        key = NewObject();
        return CKR.CKR_OK;
    }

    protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
    {
        Mechanism(mechanism);
        return CKR.CKR_OK;
    }

    protected override CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> encryptedData, ref NativeCULong encryptedDataLen)
    {
        if (!encryptedData.IsNull)
        {
            if ((ulong)encryptedDataLen < (ulong)data.Length)
            {
                encryptedDataLen = (NativeCULong)data.Length;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }
            data.CopyTo(encryptedData.Span);
        }
        encryptedDataLen = (NativeCULong)data.Length;
        return CKR.CKR_OK;
    }
}
