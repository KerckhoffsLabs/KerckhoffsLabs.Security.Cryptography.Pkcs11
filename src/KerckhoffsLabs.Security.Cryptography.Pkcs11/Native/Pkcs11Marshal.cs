using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Runtime dispatcher for PKCS#11 struct marshalling. On Linux/macOS, every operation
/// uses the unified type <c>T</c> directly. On Windows, operations route through the
/// generator-emitted <c>PackedDispatch</c> class which hard-codes the <c>T_Windows</c>
/// sibling conversions — no reflection, no <c>[RequiresDynamicCode]</c>.
/// </summary>
internal static class Pkcs11Marshal
{
    public static readonly bool IsWindows = OperatingSystem.IsWindows();

    /// <summary>
    /// Returns the on-wire size of <typeparamref name="T"/>: the Windows-packed sibling
    /// size on Windows, the natural size on Linux/macOS.
    /// </summary>
    /// <remarks>
    /// Uses the blittable size rather than the runtime-marshalling size. Every native struct is
    /// verified to have an identical managed and marshalled layout by
    /// <c>NativeStructLayoutTests.EveryCkStruct_ManagedSizeMatchesMarshalledSize</c>, and the
    /// blittable layout is the one that governs under <c>[assembly: DisableRuntimeMarshalling]</c>.
    /// </remarks>
    public static int SizeOf<T>() where T : struct
        => IsWindows && IsPackedForPkcs11(typeof(T)) ? PackedDispatch.SizeOfWindows<T>() : Unsafe.SizeOf<T>();

    /// <summary>
    /// Marshals <paramref name="value"/> into the unmanaged buffer at <paramref name="ptr"/>,
    /// using the Windows-packed sibling layout when running on Windows.
    /// The buffer must already be allocated and at least <see cref="SizeOf{T}"/> bytes.
    /// </summary>
    public static void WriteStructure<T>(IntPtr ptr, in T value) where T : struct
    {
        if (IsWindows && IsPackedForPkcs11(typeof(T)))
            PackedDispatch.WriteWindows(ptr, in value);
        else
            Marshal.StructureToPtr(value, ptr, fDeleteOld: false);
    }

    /// <summary>
    /// Reads a struct of type <typeparamref name="T"/> from the unmanaged buffer at
    /// <paramref name="ptr"/>, dispatching to the Windows-packed sibling layout on Windows
    /// and round-tripping back to the unified type via the generator-emitted converter.
    /// </summary>
    /// <remarks>
    /// The <c>[DynamicallyAccessedMembers]</c> constraint on <typeparamref name="T"/> satisfies
    /// the trimmer's requirement for <see cref="Marshal.PtrToStructure{T}(nint)"/> on the
    /// non-Windows code path. Struct types always have constructors, so no caller is burdened.
    /// </remarks>
    public static T ReadStructure<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors | DynamicallyAccessedMemberTypes.NonPublicConstructors)] T>(IntPtr ptr) where T : struct
        => IsWindows && IsPackedForPkcs11(typeof(T)) ? PackedDispatch.ReadWindows<T>(ptr) : Marshal.PtrToStructure<T>(ptr);

    /// <summary>
    /// Returns <c>true</c> when <paramref name="t"/> carries <see cref="PackedForPkcs11Attribute"/>
    /// (i.e. the generator emitted a Windows-packed sibling for it). Types without a sibling —
    /// e.g. <c>CK_VERSION</c>, which is blittable and identical on every platform — must use the
    /// natural <see cref="Marshal"/> path even on Windows. Uses <c>Type.IsDefined</c>, which only
    /// reads the metadata token — AOT-safe, no dynamic code.
    /// </summary>
    private static bool IsPackedForPkcs11(Type t) =>
        t.IsDefined(typeof(PackedForPkcs11Attribute), inherit: false);
}
