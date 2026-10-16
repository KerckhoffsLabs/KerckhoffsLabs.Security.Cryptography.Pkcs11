using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

/// <summary>
/// Answers a <c>C_GetAttributeValue</c> for <c>CKA_KEY_TYPE</c> in a fake. The session reads it before
/// every ECDH derivation or KEM, so a fake that accepts those calls must answer it.
/// </summary>
internal static class KeyTypeAttribute
{
    /// <summary>Fills every attribute of <paramref name="template"/> with <paramref name="keyType"/>, following the two-call protocol.</summary>
    public static CKR Answer(Span<CK_ATTRIBUTE> template, CKK keyType)
    {
        using var encoded = new ObjectAttribute(CKA.CKA_KEY_TYPE, (ulong)keyType);
        byte[] value = encoded.GetValueAsByteArray();
        for (int i = 0; i < template.Length; i++)
        {
            // Pass 1 (value == NULL): report the size. Pass 2: copy into the caller's buffer.
            if (template[i].value != IntPtr.Zero)
                UnmanagedMemory.Write(template[i].value, value);
            template[i].valueLen = (NativeCULong)(ulong)value.Length;
        }
        return CKR.CKR_OK;
    }
}
