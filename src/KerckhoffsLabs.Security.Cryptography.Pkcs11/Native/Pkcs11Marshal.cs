using System.Runtime.CompilerServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Runtime dispatcher for PKCS#11 struct marshalling. On Linux/macOS, every operation
/// uses the unified type <c>T</c> directly. On Windows, operations route through the
/// generator-emitted <c>PackedDispatch</c> class which hard-codes the <c>T_Windows</c>
/// sibling conversions — no reflection, no <c>[RequiresDynamicCode]</c>.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S6640:Using unsafe code blocks is security-sensitive",
    Justification = "This type is the platform layout switch: it copies structs to and from unmanaged "
    + "memory using the Pack=1 sibling layout on Windows and the natural layout elsewhere. Both "
    + "paths dereference a raw IntPtr, which C# permits only in unsafe code. Suppressed at the type "
    + "so the rule keeps its value elsewhere. The copies are blittable by construction — the "
    + "unmanaged constraint enforces it at compile time — and no longer route through the runtime "
    + "marshaller, so there is no reflection and no layout reinterpretation to get wrong.")]
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
    /// blittable layout is the one that governs under <c>[assembly: DisableRuntimeMarshalling]</c>
    /// and the one this type reads and writes.
    /// </remarks>
    public static int SizeOf<T>() where T : unmanaged
        => IsWindows && Packed<T>.Value ? PackedDispatch.SizeOfWindows<T>() : Unsafe.SizeOf<T>();

    /// <summary>
    /// Marshals <paramref name="value"/> into the unmanaged buffer at <paramref name="ptr"/>,
    /// using the Windows-packed sibling layout when running on Windows.
    /// The buffer must already be allocated and at least <see cref="SizeOf{T}"/> bytes.
    /// </summary>
    public static void WriteStructure<T>(IntPtr ptr, in T value) where T : unmanaged
    {
        if (IsWindows && Packed<T>.Value)
            PackedDispatch.WriteWindows(ptr, in value);
        else
            unsafe { Unsafe.WriteUnaligned((void*)ptr, value); }
    }

    /// <summary>
    /// Reads a struct of type <typeparamref name="T"/> from the unmanaged buffer at
    /// <paramref name="ptr"/>, dispatching to the Windows-packed sibling layout on Windows
    /// and round-tripping back to the unified type via the generator-emitted converter.
    /// </summary>
    /// <remarks>
    /// The non-Windows path is a blittable copy rather than <c>Marshal.PtrToStructure</c>: the
    /// <c>unmanaged</c> constraint makes that sound by construction, and it needs no
    /// <c>[DynamicallyAccessedMembers]</c> annotation because nothing reflects over
    /// <typeparamref name="T"/>.
    /// </remarks>
    public static T ReadStructure<T>(IntPtr ptr) where T : unmanaged
    {
        if (IsWindows && Packed<T>.Value)
            return PackedDispatch.ReadWindows<T>(ptr);

        unsafe { return Unsafe.ReadUnaligned<T>((void*)ptr); }
    }

    /// <summary>
    /// Returns <c>true</c> when <paramref name="t"/> carries <see cref="PackedForPkcs11Attribute"/>
    /// (i.e. the generator emitted a Windows-packed sibling for it). Types without a sibling —
    /// e.g. <c>CK_VERSION</c>, which is blittable and identical on every platform — must use the
    /// natural (unified-layout) path even on Windows. Uses <c>Type.IsDefined</c>, which only
    /// reads the metadata token — AOT-safe, no dynamic code.
    /// </summary>
    /// <remarks>
    /// The generic paths must go through <see cref="Packed{T}"/> instead: this walks the custom
    /// attribute blob on every call, which is not something the per-element marshalling loops in
    /// <c>ObjectAttribute</c> and <c>MechanismParameterScope</c> should pay. Only the reflective
    /// <c>Type</c>-based entry points on <see cref="UnmanagedMemory"/>, which have no type
    /// parameter to key a cache on, call this directly.
    /// </remarks>
    internal static bool IsPackedForPkcs11(Type t) =>
        t.IsDefined(typeof(PackedForPkcs11Attribute), inherit: false);

    /// <summary>
    /// Per-instantiation cache of the <see cref="IsPackedForPkcs11(Type)"/> lookup.
    /// </summary>
    /// <remarks>
    /// A <c>static readonly</c> field of a generic type is initialized once per closed type and is
    /// visible to the JIT as a constant, so <c>IsWindows &amp;&amp; Packed&lt;T&gt;.Value</c> folds
    /// away entirely and the branch costs nothing at the call site. The alternative — calling
    /// <c>Type.IsDefined</c> per operation — walks metadata every time.
    /// </remarks>
    private static class Packed<T> where T : unmanaged
    {
        internal static readonly bool Value = IsPackedForPkcs11(typeof(T));
    }
}
