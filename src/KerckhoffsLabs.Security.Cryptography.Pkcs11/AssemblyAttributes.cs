// Disables the runtime marshalling subsystem for this assembly's interop boundaries
// (P/Invoke, [LibraryImport], and delegate*-unmanaged calls). Every cryptoki call now
// passes only blittable types — the BL-060 migration replaced all [UnmanagedFunctionPointer]
// delegates with delegate* unmanaged[Cdecl] dispatch (manual bool->byte, pinned arrays,
// mechanism params crossing as IntPtr) and made the *_INFO structs blittable via [InlineArray].
//
// Effects:
//  - Smaller Native AOT output: no per-call runtime-marshalling stubs are generated.
//  - Compiler-enforced invariant: any future non-blittable interop boundary becomes a build
//    error, structurally preventing the marshalling-corruption class of bug.
//  - bool/char at interop boundaries are blittable (1-byte bool, not the 4-byte Win32 BOOL).
//    This assembly passes no bool/char across a boundary (C_GetSlotList's tokenPresent is
//    converted to byte in the wrapper), so the change is inert here.
//
// The explicit System.Runtime.InteropServices.Marshal APIs (PtrToStructure/StructureToPtr/
// SizeOf), used by Pkcs11Marshal/UnmanagedMemory for the packed-struct paths, are NOT governed
// by this attribute and continue to marshal as before.
[assembly: System.Runtime.CompilerServices.DisableRuntimeMarshalling]
