namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Marks a native interop struct as requiring a Windows-packed (<c>Pack = 1</c>) sibling.
/// Consumed by the <c>PackedStructsGenerator</c> source generator, which emits a parallel
/// <c>T_Windows</c> partial struct in the same namespace. Runtime dispatch happens in
/// <see cref="Pkcs11Marshal"/> based on <c>OperatingSystem.IsWindows()</c>.
/// </summary>
/// <remarks>
/// The decorated struct MUST carry <c>[StructLayout(LayoutKind.Sequential)]</c> explicitly.
/// This attribute is a marker only — it does NOT itself set the layout. The struct need not be
/// <see langword="partial"/>: the generator emits the <c>T_Windows</c> sibling as a separate
/// type and never adds members to the decorated struct itself.
/// </remarks>
[AttributeUsage(AttributeTargets.Struct, AllowMultiple = false, Inherited = false)]
internal sealed class PackedForPkcs11Attribute : Attribute
{
}
