namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Marks a native interop struct as requiring a Windows-packed (<c>Pack = 1</c>) sibling.
/// Consumed by the <c>PackedStructsGenerator</c> source generator, which emits a parallel
/// <c>T_Windows</c> partial struct in the same namespace. Runtime dispatch happens in
/// <see cref="Pkcs11Marshal"/> based on <c>OperatingSystem.IsWindows()</c>.
/// </summary>
/// <remarks>
/// The decorated struct MUST be declared <c>partial</c> and MUST carry
/// <c>[StructLayout(LayoutKind.Sequential)]</c> explicitly. This attribute is a marker
/// only — it does NOT itself set the layout.
/// </remarks>
[AttributeUsage(AttributeTargets.Struct, AllowMultiple = false, Inherited = false)]
internal sealed class PackedForPkcs11Attribute : Attribute
{
}
