using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Runtime dispatcher for PKCS#11 struct marshalling. On Linux/macOS, every operation
/// uses the unified type <c>T</c> directly. On Windows, when a generated <c>T_Windows</c>
/// sibling exists (via <see cref="PackedForPkcs11Attribute"/> + the source generator),
/// operations route through that sibling so the <c>Pack = 1</c> layout matches the
/// OASIS-conformant Windows PKCS#11 ABI.
/// </summary>
internal static class Pkcs11Marshal
{
    public static readonly bool IsWindows = OperatingSystem.IsWindows();

    public static int SizeOf<T>() where T : struct => SiblingCache<T>.Size;

    private static class SiblingCache<T> where T : struct
    {
        public static readonly Type? WindowsType;
        public static readonly int Size;
        public static readonly MethodInfo? FromUnified; // static method on T_Windows: T_Windows FromUnified(in T)
        public static readonly MethodInfo? ToUnified;   // instance method on T_Windows: T ToUnified()

        static SiblingCache()
        {
            var asm = typeof(T).Assembly;
            var winName = typeof(T).FullName + "_Windows";
            WindowsType = asm.GetType(winName);

            if (WindowsType is not null)
            {
                FromUnified = WindowsType.GetMethod("FromUnified",
                    BindingFlags.Public | BindingFlags.Static, binder: null,
                    types: [typeof(T).MakeByRefType()], modifiers: null);
                ToUnified = WindowsType.GetMethod("ToUnified",
                    BindingFlags.Public | BindingFlags.Instance, binder: null,
                    types: Type.EmptyTypes, modifiers: null);
            }

            Size = (IsWindows && WindowsType is not null)
                ? Marshal.SizeOf(WindowsType)
                : Marshal.SizeOf<T>();
        }
    }
}
