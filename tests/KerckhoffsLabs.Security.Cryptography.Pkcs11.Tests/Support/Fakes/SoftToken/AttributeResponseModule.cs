using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

/// <summary>
/// Minimal <see cref="FakeModule"/> that answers every <c>C_GetAttributeValue</c> query via a
/// caller-supplied responder — including a fatal <see cref="CKR"/> a real backend cannot be coaxed
/// into returning for a well-formed key object's required attributes. A <c>respondFor</c> responder, given
/// the object's handle too, takes the place of <c>respond</c>. Every other function is absent,
/// so the library sees <c>CKR_FUNCTION_NOT_SUPPORTED</c> for it, except <c>C_Decrypt</c> when a <c>decrypt</c>
/// answer is given; <c>C_Initialize</c>/<c>C_Finalize</c>
/// succeed, and disposing the library from <see cref="FakeModule.Load(Pkcs11LibraryOptions?)"/> releases the module. See
/// <see cref="FakeKeys.Create"/>.
/// </summary>
internal sealed class AttributeResponseModule(
    Func<CKA, (CKR Rv, byte[]? Value)> respond,
    Func<byte[], byte[]>? decrypt = null,
    Func<ulong, CKA, (CKR Rv, byte[]? Value)>? respondFor = null) : FakeModule
{
    protected override bool ReleasedByFinalize => true;

    protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template)
    {
        for (int i = 0; i < template.Length; i++)
        {
            var type = (CKA)(ulong)template[i].type;
            (CKR rv, byte[]? value) = respondFor is null ? respond(type) : respondFor((ulong)objectId, type);
            if (rv != CKR.CKR_OK)
            {
                // PKCS#11 sentinel: ulValueLen = (CK_ULONG)-1 marks an unavailable attribute —
                // matches ManagedSoftToken's convention for the non-fatal case.
                template[i].valueLen = NativeCULong.MaxValue;
                return rv;
            }

            // Pass 1 (value == NULL): report the size. Pass 2: copy into the caller's buffer.
            if (template[i].value != IntPtr.Zero)
                UnmanagedMemory.Write(template[i].value, value!);
            template[i].valueLen = (NativeCULong)(ulong)value!.Length;
        }
        return CKR.CKR_OK;
    }

    // With a decrypt answer, C_DecryptInit accepts any mechanism and C_Decrypt answers CKR_OK with whatever
    // it returns, as a token that checks nothing would. Without one, both are unsupported, as when absent.
    protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        => decrypt is null ? CKR.CKR_FUNCTION_NOT_SUPPORTED : CKR.CKR_OK;

    protected override CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, NativeBuffer<byte> data, ref NativeCULong dataLen)
    {
        if (decrypt is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        byte[] plaintext = decrypt(encryptedData.ToArray());
        dataLen = (NativeCULong)(ulong)plaintext.Length;
        if (data.IsNull)
            return CKR.CKR_OK;
        if (data.Span.Length < plaintext.Length)
            return CKR.CKR_BUFFER_TOO_SMALL;
        plaintext.CopyTo(data.Span);
        return CKR.CKR_OK;
    }
}
