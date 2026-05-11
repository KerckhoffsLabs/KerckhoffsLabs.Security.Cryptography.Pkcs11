namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

#if WINDOWS
[StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
#else
[StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
#endif
internal sealed class PlatformSpecificPackAttribute : Attribute
{
}