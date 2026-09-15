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
    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_MessageSignInit</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_MessageSignInit => _fp.C_MessageSignInit is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_SignMessage</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_SignMessage => _fp.C_SignMessage is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_SignMessageBegin</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_SignMessageBegin => _fp.C_SignMessageBegin is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_SignMessageNext</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_SignMessageNext => _fp.C_SignMessageNext is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_MessageSignFinal</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_MessageSignFinal => _fp.C_MessageSignFinal is not null;

    /// <summary>Wrapper for <c>C_MessageSignInit</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_MessageSignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_MessageSignInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_MessageSignInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_MessageSignInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_MessageSignInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_SignMessage</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_SignMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
        Span<byte> signature, out NativeCULong signatureLen)
    {
        signatureLen = (NativeCULong)signature.Length;
        ThrowIfUnbound(_fp.C_SignMessage);
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
        fixed (NativeCULong* sigLenPtr = &signatureLen)
            return _fp.C_SignMessage(session, parameter, parameterLen, dataPtr, (NativeCULong)data.Length, sigPtr, sigLenPtr);
    }

    /// <summary>Wrapper for <c>C_SignMessageBegin</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_SignMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen)
    {
        ThrowIfUnbound(_fp.C_SignMessageBegin);
        return _fp.C_SignMessageBegin(session, parameter, parameterLen);
    }

    /// <summary>Wrapper for <c>C_SignMessageNext</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_SignMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
        Span<byte> signature, out NativeCULong signatureLen)
    {
        signatureLen = (NativeCULong)signature.Length;
        ThrowIfUnbound(_fp.C_SignMessageNext);
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
        fixed (NativeCULong* sigLenPtr = &signatureLen)
            return _fp.C_SignMessageNext(session, parameter, parameterLen, dataPtr, (NativeCULong)data.Length, sigPtr, sigLenPtr);
    }

    /// <summary>Wrapper for <c>C_MessageSignFinal</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_MessageSignFinal(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_MessageSignFinal);
        return _fp.C_MessageSignFinal(session);
    }
}
