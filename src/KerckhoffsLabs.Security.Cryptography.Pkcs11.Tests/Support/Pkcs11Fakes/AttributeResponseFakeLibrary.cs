using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

/// <summary>
/// Minimal <see cref="ILowLevelPkcs11Library"/> fake that answers every <c>C_GetAttributeValue</c>
/// query via a caller-supplied responder — including a fatal <see cref="CKR"/> a real backend
/// cannot be coaxed into returning for a well-formed key object's required attributes. Everything
/// else falls back to <see cref="NotSupportedPkcs11Library"/>'s <c>CKR_FUNCTION_NOT_SUPPORTED</c>,
/// except <c>C_Initialize</c>/<c>C_Finalize</c>, which must succeed for <c>Pkcs11Library</c>'s
/// constructor and <c>Dispose</c> to work. See <see cref="FakeKeys.Create"/>.
/// </summary>
internal sealed class AttributeResponseFakeLibrary(Func<CKA, (CKR Rv, byte[]? Value)> respond) : NotSupportedPkcs11Library
{
    public override CKR C_Initialize(CK_C_INITIALIZE_ARGS? initArgs) => CKR.CKR_OK;
    public override CKR C_Finalize(IntPtr reserved) => CKR.CKR_OK;

    public override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template)
    {
        for (int i = 0; i < template.Length; i++)
        {
            (CKR rv, byte[]? value) = respond((CKA)(ulong)template[i].type);
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
}
