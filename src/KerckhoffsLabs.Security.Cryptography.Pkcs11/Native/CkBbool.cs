namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// <c>CK_BBOOL</c>: one byte, <c>CK_FALSE</c> (0) or <c>CK_TRUE</c> (1). Interop structs declare such
/// fields as <see langword="byte"/>, not <see langword="bool"/>: with runtime marshalling disabled,
/// <c>[MarshalAs(U1)]</c> is ignored, and a byte a module writes other than 0 or 1 would be an
/// invalid .NET <see langword="bool"/>.
/// </summary>
internal static class CkBbool
{
    public const byte False = 0;
    public const byte True = 1;

    public static byte From(bool value) => value ? True : False;
}
