using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

/// <summary>
/// Answers a <c>C_GetAttributeValue</c> for the attributes the session reads to describe a key's strength
/// (<c>CKA_KEY_TYPE</c>, <c>CKA_VALUE_LEN</c>, <c>CKA_PARAMETER_SET</c>, <c>CKA_HSS_LEVELS</c>), each a
/// <c>CK_ULONG</c>, following the two-call protocol as <see cref="KeyTypeAttribute.Answer"/> does.
/// </summary>
internal static class KeyStrengthAttributes
{
    /// <summary>
    /// Fills every attribute of <paramref name="template"/> from <paramref name="values"/>. A
    /// <see langword="null"/> value answers <c>CK_UNAVAILABLE_INFORMATION</c> (the length sentinel, with
    /// <c>CKR_OK</c>); an attribute <paramref name="values"/> does not hold answers <c>CKR_ATTRIBUTE_TYPE_INVALID</c>.
    /// </summary>
    public static CKR Answer(Span<CK_ATTRIBUTE> template, IReadOnlyDictionary<CKA, ulong?> values)
        => Answer(template, values, sensitive: null);

    /// <summary>
    /// As <see cref="Answer(Span{CK_ATTRIBUTE}, IReadOnlyDictionary{CKA, ulong?})"/>, but each attribute in
    /// <paramref name="sensitive"/> answers <c>CKR_ATTRIBUTE_SENSITIVE</c>.
    /// </summary>
    public static CKR Answer(Span<CK_ATTRIBUTE> template, IReadOnlyDictionary<CKA, ulong?> values, IReadOnlySet<CKA>? sensitive)
    {
        CKR rv = CKR.CKR_OK;
        for (int i = 0; i < template.Length; i++)
        {
            var type = (CKA)(ulong)template[i].type;
            if (sensitive?.Contains(type) == true)
            {
                template[i].valueLen = NativeCULong.MaxValue;
                rv = CKR.CKR_ATTRIBUTE_SENSITIVE;
                continue;
            }
            if (!values.TryGetValue(type, out ulong? value))
            {
                template[i].valueLen = NativeCULong.MaxValue;
                if (rv == CKR.CKR_OK)
                    rv = CKR.CKR_ATTRIBUTE_TYPE_INVALID;
                continue;
            }
            if (value is null)
            {
                template[i].valueLen = (NativeCULong)CK.CK_UNAVAILABLE_INFORMATION;
                continue;
            }

            using var encoded = new ObjectAttribute(type, value.Value);
            byte[] bytes = encoded.GetValueAsByteArray();
            // Pass 1 (value == NULL): report the size. Pass 2: copy into the caller's buffer.
            if (template[i].value != IntPtr.Zero)
                UnmanagedMemory.Write(template[i].value, bytes);
            template[i].valueLen = (NativeCULong)(ulong)bytes.Length;
        }
        return rv;
    }
}
