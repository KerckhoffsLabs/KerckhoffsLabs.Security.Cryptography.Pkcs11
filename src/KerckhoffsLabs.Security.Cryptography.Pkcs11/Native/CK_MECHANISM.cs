using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Specifies a particular mechanism and any parameters it requires
/// </summary>
[StructLayout(LayoutKind.Sequential)]
[PackedForPkcs11]
internal partial struct CK_MECHANISM
{
    /// <summary>
    /// The type of mechanism
    /// </summary>
    public NativeCULong Mechanism;

    /// <summary>
    /// Pointer to the parameter if required by the mechanism
    /// </summary>
    public IntPtr Parameter;

    /// <summary>
    /// Length of the parameter in bytes
    /// </summary>
    public NativeCULong ParameterLen;

    /// <summary>
    /// Creates mechanism of given type with no parameter
    /// </summary>
    /// <param name="mechanism">Mechanism type</param>
    /// <returns>Mechanism of given type with no parameter</returns>
    internal static CK_MECHANISM CreateMechanism(CKM mechanism) => CreateMechanism(mechanism.ToCULong());

    /// <summary>
    /// Creates mechanism of given type with no parameter
    /// </summary>
    /// <param name="mechanism">Mechanism type</param>
    /// <returns>Mechanism of given type with no parameter</returns>
    internal static CK_MECHANISM CreateMechanism(NativeCULong mechanism) => CreateMechanism(mechanism, []);

    /// <summary>
    /// Creates mechanism of given type with byte array parameter
    /// </summary>
    /// <param name="mechanism">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    /// <returns>Mechanism of given type with byte array parameter</returns>
    internal static CK_MECHANISM CreateMechanism(CKM mechanism, byte[]? parameter)
        => CreateMechanism(mechanism.ToCULong(), (ReadOnlySpan<byte>)(parameter ?? []));

    /// <summary>
    /// Creates mechanism of given type with byte array parameter
    /// </summary>
    /// <param name="mechanism">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    /// <returns>Mechanism of given type with byte array parameter</returns>
    internal static CK_MECHANISM CreateMechanism(NativeCULong mechanism, byte[]? parameter)
        => CreateMechanism(mechanism, (ReadOnlySpan<byte>)(parameter ?? []));

    /// <summary>
    /// Creates mechanism of given type with span parameter
    /// </summary>
    /// <param name="mechanism">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    /// <returns>Mechanism of given type with span parameter</returns>
    internal static CK_MECHANISM CreateMechanism(CKM mechanism, ReadOnlySpan<byte> parameter)
        => CreateMechanism(mechanism.ToCULong(), parameter);

    /// <summary>
    /// Creates mechanism of given type with span parameter
    /// </summary>
    /// <param name="mechanism">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    /// <returns>Mechanism of given type with span parameter</returns>
    internal static CK_MECHANISM CreateMechanism(NativeCULong mechanism, ReadOnlySpan<byte> parameter)
    {
        CK_MECHANISM mech = new() { Mechanism = mechanism };
        if (parameter.Length > 0)
        {
            mech.Parameter = UnmanagedMemory.Allocate(parameter.Length);
            UnmanagedMemory.Write(mech.Parameter, parameter);
            mech.ParameterLen = (NativeCULong)parameter.Length;
        }
        else
        {
            mech.Parameter = IntPtr.Zero;
            mech.ParameterLen = (NativeCULong)0;
        }
        return mech;
    }

    /// <summary>
    /// Creates mechanism of given type with structure as parameter
    /// </summary>
    /// <param name="mechanism">Mechanism type</param>
    /// <param name="parameterStructure">Structure with mechanism parameters</param>
    /// <returns>Mechanism of given type with structure as parameter</returns>
    internal static CK_MECHANISM CreateMechanism(CKM mechanism, object parameterStructure)
    {
        ArgumentNullException.ThrowIfNull(parameterStructure);

        return CreateMechanism(mechanism.ToCULong(), parameterStructure);
    }

    /// <summary>
    /// Creates mechanism of given type with structure as parameter
    /// </summary>
    /// <param name="mechanism">Mechanism type</param>
    /// <param name="parameterStructure">Structure with mechanism parameters</param>
    /// <returns>Mechanism of given type with structure as parameter</returns>
    internal static CK_MECHANISM CreateMechanism(NativeCULong mechanism, object parameterStructure)
    {
        ArgumentNullException.ThrowIfNull(parameterStructure);
        CK_MECHANISM mech = new()
        {
            Mechanism = mechanism,
            ParameterLen = (NativeCULong)UnmanagedMemory.SizeOf(parameterStructure.GetType())
        };
        mech.Parameter = UnmanagedMemory.Allocate((int)mech.ParameterLen);
        UnmanagedMemory.Write(mech.Parameter, parameterStructure);
        return mech;
    }
}
