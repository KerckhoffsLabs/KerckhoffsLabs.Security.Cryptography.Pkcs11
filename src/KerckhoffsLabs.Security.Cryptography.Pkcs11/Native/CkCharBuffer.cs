using System.Runtime.CompilerServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>Blittable inline 16-byte buffer (replaces <c>[MarshalAs(ByValArray, SizeConst=16)] byte[]</c>).</summary>
[InlineArray(16)]
internal struct CkChar16 { private byte _e0; }

/// <summary>Blittable inline 32-byte buffer.</summary>
[InlineArray(32)]
internal struct CkChar32 { private byte _e0; }

/// <summary>Blittable inline 64-byte buffer.</summary>
[InlineArray(64)]
internal struct CkChar64 { private byte _e0; }
