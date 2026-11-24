using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

/// <summary>Answers one <c>C_GetAttributeValue</c> call: <paramref name="call"/> counts from 0.</summary>
internal delegate CKR TemplateAnswer(int call, Span<CK_ATTRIBUTE> template);

/// <summary>
/// A module whose <c>C_GetAttributeValue</c> is whatever the test writes into the caller's template, for the
/// readers that hand the module fixed-size buffers: what a module may write, at any length, with any code.
/// <see cref="Attributes"/> writes the common answers.
/// </summary>
internal sealed class TemplateAnswerModule(TemplateAnswer answer) : FakeModule
{
    private int _calls;

    protected override bool ReleasedByFinalize => true;

    protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template)
        => answer(_calls++, template);

    /// <summary>Runs <paramref name="body"/> with the low-level library over this module.</summary>
    public T With<T>(Func<LowLevelPkcs11Library, T> body)
    {
        using Pkcs11Library library = Load();
        return body(library.LowLevelLibrary!);
    }
}

/// <summary>Writes into a <c>CK_ATTRIBUTE</c> as a module would.</summary>
internal static unsafe class Attributes
{
    /// <summary>The template entry for <paramref name="type"/>.</summary>
    public static ref CK_ATTRIBUTE Find(Span<CK_ATTRIBUTE> template, CKA type)
    {
        for (int i = 0; i < template.Length; i++)
        {
            if ((CKA)(ulong)template[i].type == type)
                return ref template[i];
        }
        throw new InvalidOperationException($"The template has no {type}.");
    }

    /// <summary>A <c>CK_ULONG</c> value, at its length.</summary>
    public static void Ulong(ref CK_ATTRIBUTE attribute, ulong value)
    {
        *(NativeCULong*)attribute.value = (NativeCULong)value;
        attribute.valueLen = (NativeCULong)(ulong)sizeof(NativeCULong);
    }

    /// <summary>
    /// <paramref name="value"/>, or its length alone for a length query (a null pointer); a buffer too small
    /// gets <c>CK_UNAVAILABLE_INFORMATION</c> and <c>CKR_BUFFER_TOO_SMALL</c>, as PKCS#11 v3.2 has it.
    /// </summary>
    public static CKR Bytes(ref CK_ATTRIBUTE attribute, ReadOnlySpan<byte> value)
    {
        if (attribute.value != IntPtr.Zero)
        {
            if ((ulong)attribute.valueLen < (ulong)value.Length)
            {
                attribute.valueLen = NativeCULong.MaxValue;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }
            value.CopyTo(new Span<byte>((void*)attribute.value, value.Length));
        }
        attribute.valueLen = (NativeCULong)(ulong)value.Length;
        return CKR.CKR_OK;
    }

    /// <summary>A <c>CK_BBOOL</c>.</summary>
    public static void Bool(ref CK_ATTRIBUTE attribute, bool value) => Bytes(ref attribute, [value ? (byte)1 : (byte)0]);

    /// <summary>No value: <c>CK_UNAVAILABLE_INFORMATION</c>, as for an attribute absent or sensitive.</summary>
    public static void Unavailable(ref CK_ATTRIBUTE attribute) => attribute.valueLen = NativeCULong.MaxValue;
}
