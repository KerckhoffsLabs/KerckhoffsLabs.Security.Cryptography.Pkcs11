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
    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_MessageVerifyInit</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_MessageVerifyInit => _fp.C_MessageVerifyInit is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_VerifyMessage</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_VerifyMessage => _fp.C_VerifyMessage is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_VerifyMessageBegin</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_VerifyMessageBegin => _fp.C_VerifyMessageBegin is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_VerifyMessageNext</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_VerifyMessageNext => _fp.C_VerifyMessageNext is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_MessageVerifyFinal</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_MessageVerifyFinal => _fp.C_MessageVerifyFinal is not null;

    /// <summary>Wrapper for <c>C_MessageVerifyInit</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_MessageVerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_MessageVerifyInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_MessageVerifyInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_MessageVerifyInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_MessageVerifyInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_VerifyMessage</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifyMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        ThrowIfUnbound(_fp.C_VerifyMessage);
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
            return _fp.C_VerifyMessage(session, parameter, parameterLen, dataPtr, (NativeCULong)data.Length, sigPtr, (NativeCULong)signature.Length);
    }

    /// <summary>Wrapper for <c>C_VerifyMessageBegin</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifyMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen)
    {
        ThrowIfUnbound(_fp.C_VerifyMessageBegin);
        return _fp.C_VerifyMessageBegin(session, parameter, parameterLen);
    }

    /// <summary>Wrapper for <c>C_VerifyMessageNext</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifyMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        ThrowIfUnbound(_fp.C_VerifyMessageNext);
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
            return _fp.C_VerifyMessageNext(session, parameter, parameterLen, dataPtr, (NativeCULong)data.Length, sigPtr, (NativeCULong)signature.Length);
    }

    /// <summary>Wrapper for <c>C_MessageVerifyFinal</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_MessageVerifyFinal(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_MessageVerifyFinal);
        return _fp.C_MessageVerifyFinal(session);
    }
}
