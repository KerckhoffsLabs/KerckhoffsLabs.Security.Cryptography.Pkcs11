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
    // DER of the P-256 OID (1.2.840.10045.3.1.7): the curve an EC key of these fakes is on.
    private static readonly byte[] P256EcParams = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    /// <summary>
    /// Answers <paramref name="template"/> for a key of <paramref name="keyType"/>, following the two-call protocol:
    /// <c>CKA_KEY_TYPE</c>, an EC key's <c>CKA_EC_PARAMS</c> (P-256), and every other attribute as one the key does not
    /// have (<c>CKR_ATTRIBUTE_TYPE_INVALID</c>), as a token does.
    /// </summary>
    public static CKR Answer(Span<CK_ATTRIBUTE> template, CKK keyType)
    {
        using var encoded = new ObjectAttribute(CKA.CKA_KEY_TYPE, (ulong)keyType);
        byte[] keyTypeValue = encoded.GetValueAsByteArray();
        CKR rv = CKR.CKR_OK;
        for (int i = 0; i < template.Length; i++)
        {
            byte[]? value = (CKA)(ulong)template[i].type switch
            {
                CKA.CKA_KEY_TYPE => keyTypeValue,
                CKA.CKA_EC_PARAMS when keyType == CKK.CKK_EC => P256EcParams,
                _ => null,
            };
            if (value is null)
            {
                // An attribute the key does not have, as a token answers it (PKCS#11 v3.2 C_GetAttributeValue).
                template[i].valueLen = NativeCULong.MaxValue;
                rv = CKR.CKR_ATTRIBUTE_TYPE_INVALID;
                continue;
            }
            // Pass 1 (value == NULL): report the size. Pass 2: copy into the caller's buffer.
            if (template[i].value != IntPtr.Zero)
                UnmanagedMemory.Write(template[i].value, value);
            template[i].valueLen = (NativeCULong)(ulong)value.Length;
        }
        return rv;
    }
}
