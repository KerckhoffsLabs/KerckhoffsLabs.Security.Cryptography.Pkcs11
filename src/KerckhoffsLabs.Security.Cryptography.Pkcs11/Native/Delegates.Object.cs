// <auto-split-from Delegates.cs>

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S6640:Using unsafe code blocks is security-sensitive",
    Justification = "This type IS the cryptoki dispatch boundary, and every unsafe region in it is one of " +
    "exactly three things C# permits nowhere else: invoking an unmanaged function pointer, pinning a managed " +
    "buffer for the duration of a native call, and taking the address of a blittable struct to pass as a " +
    "CK_*_PTR. There is no version of this file that satisfies the rule and still dispatches to a PKCS#11 " +
    "module. Suppressed at the type rather than per member so the rule keeps its value everywhere else: an " +
    "unsafe block appearing outside this boundary is still reported, and that is the case worth reviewing. " +
    "The safety argument does not rest on the suppression — every pointer is either pinned by a fixed " +
    "statement scoped to the call, or the address of a local, and every function pointer is null-checked by " +
    "ThrowIfUnbound before invocation. The dispatch table's binding is covered hermetically by " +
    "DelegatesLoaderTests, and the wrappers themselves by the full suite against SoftHSM2 and opencryptoki.")]
internal partial class Delegates
{
    /// <summary>Wrapper for <c>C_CreateObject</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_CreateObject(NativeCULong session, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong objectId)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_CreateObject_Windows);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
            fixed (NativeCULong* idPtr = &objectId)
                return _fp.C_CreateObject_Windows(session, t, (NativeCULong)template.Length, idPtr);
        }

        ThrowIfUnbound(_fp.C_CreateObject);
        fixed (CK_ATTRIBUTE* t = template)
        fixed (NativeCULong* idPtr = &objectId)
            return _fp.C_CreateObject(session, t, (NativeCULong)template.Length, idPtr);
    }

    /// <summary>Wrapper for <c>C_CopyObject</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_CopyObject(NativeCULong session, NativeCULong objectId, ReadOnlySpan<CK_ATTRIBUTE> template,
        ref NativeCULong newObjectId)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_CopyObject_Windows);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
            fixed (NativeCULong* idPtr = &newObjectId)
                return _fp.C_CopyObject_Windows(session, objectId, t, (NativeCULong)template.Length, idPtr);
        }

        ThrowIfUnbound(_fp.C_CopyObject);
        fixed (CK_ATTRIBUTE* t = template)
        fixed (NativeCULong* idPtr = &newObjectId)
            return _fp.C_CopyObject(session, objectId, t, (NativeCULong)template.Length, idPtr);
    }

    /// <summary>Wrapper for <c>C_DestroyObject</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DestroyObject(NativeCULong session, NativeCULong objectId)
    {
        ThrowIfUnbound(_fp.C_DestroyObject);
        return _fp.C_DestroyObject(session, objectId);
    }

    /// <summary>Wrapper for <c>C_GetObjectSize</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size)
    {
        ThrowIfUnbound(_fp.C_GetObjectSize);
        fixed (NativeCULong* sizePtr = &size)
            return _fp.C_GetObjectSize(session, objectId, sizePtr);
    }

    /// <summary>Wrapper for <c>C_GetAttributeValue</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GetAttributeValue_Windows);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            NativeCULong winRv;
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
                winRv = _fp.C_GetAttributeValue_Windows(session, objectId, t, (NativeCULong)template.Length);
            // The token writes the value and its length back into the packed copy, so
            // mirror the result into the caller's template before returning.
            if (winTpl is not null)
                for (int i = 0; i < winTpl.Length; i++)
                    template[i] = winTpl[i].ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_GetAttributeValue);
        fixed (CK_ATTRIBUTE* t = template)
            return _fp.C_GetAttributeValue(session, objectId, t, (NativeCULong)template.Length);
    }

    /// <summary>Wrapper for <c>C_SetAttributeValue</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_SetAttributeValue(NativeCULong session, NativeCULong objectId, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_SetAttributeValue_Windows);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
                return _fp.C_SetAttributeValue_Windows(session, objectId, t, (NativeCULong)template.Length);
        }

        ThrowIfUnbound(_fp.C_SetAttributeValue);
        fixed (CK_ATTRIBUTE* t = template)
            return _fp.C_SetAttributeValue(session, objectId, t, (NativeCULong)template.Length);
    }

    /// <summary>Wrapper for <c>C_FindObjectsInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_FindObjectsInit(NativeCULong session, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_FindObjectsInit_Windows);
            CK_ATTRIBUTE_Windows[]? winTpl = ToWindowsTemplate(template);
            fixed (CK_ATTRIBUTE_Windows* t = winTpl)
                return _fp.C_FindObjectsInit_Windows(session, t, (NativeCULong)template.Length);
        }

        ThrowIfUnbound(_fp.C_FindObjectsInit);
        fixed (CK_ATTRIBUTE* t = template)
            return _fp.C_FindObjectsInit(session, t, (NativeCULong)template.Length);
    }

    /// <summary>Wrapper for <c>C_FindObjects</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_FindObjects(NativeCULong session, NativeCULong[] objectId, NativeCULong maxObjectCount, ref NativeCULong objectCount)
    {
        ThrowIfUnbound(_fp.C_FindObjects);
        fixed (NativeCULong* objPtr = objectId)
        fixed (NativeCULong* countPtr = &objectCount)
            return _fp.C_FindObjects(session, objPtr, maxObjectCount, countPtr);
    }

    /// <summary>Wrapper for <c>C_FindObjectsFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_FindObjectsFinal(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_FindObjectsFinal);
        return _fp.C_FindObjectsFinal(session);
    }
}
