using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Specifies a particular mechanism and any parameters it requires
/// </summary>
[PlatformSpecificPack]
public struct CK_MECHANISM
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
    public static CK_MECHANISM CreateMechanism(CKM mechanism)
    {
        return CreateMechanism(mechanism.ToCULong());
    }

    /// <summary>
    /// Creates mechanism of given type with no parameter
    /// </summary>
    /// <param name="mechanism">Mechanism type</param>
    /// <returns>Mechanism of given type with no parameter</returns>
    public static CK_MECHANISM CreateMechanism(NativeCULong mechanism)
    {
        return _CreateMechanism(mechanism, null);
    }

    /// <summary>
    /// Creates mechanism of given type with byte array parameter
    /// </summary>
    /// <param name="mechanism">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    /// <returns>Mechanism of given type with byte array parameter</returns>
    public static CK_MECHANISM CreateMechanism(CKM mechanism, byte[] parameter)
    {
        return CreateMechanism(mechanism.ToCULong(), parameter);
    }

    /// <summary>
    /// Creates mechanism of given type with byte array parameter
    /// </summary>
    /// <param name="mechanism">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    /// <returns>Mechanism of given type with byte array parameter</returns>
    public static CK_MECHANISM CreateMechanism(NativeCULong mechanism, byte[] parameter)
    {
        return _CreateMechanism(mechanism, parameter);
    }

    /// <summary>
    /// Creates mechanism of given type with structure as parameter
    /// </summary>
    /// <param name="mechanism">Mechanism type</param>
    /// <param name="parameterStructure">Structure with mechanism parameters</param>
    /// <returns>Mechanism of given type with structure as parameter</returns>
    public static CK_MECHANISM CreateMechanism(CKM mechanism, object parameterStructure)
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
    public static CK_MECHANISM CreateMechanism(NativeCULong mechanism, object parameterStructure)
    {
        ArgumentNullException.ThrowIfNull(parameterStructure);

        CK_MECHANISM ckMechanism = new()
        {
            Mechanism = mechanism,
            ParameterLen = new NativeCULong((uint)UnmanagedMemory.SizeOf(parameterStructure.GetType()))
        };

        ckMechanism.Parameter = UnmanagedMemory.Allocate(ConvertUtils.UInt32ToInt32(ckMechanism.ParameterLen));
        UnmanagedMemory.Write(ckMechanism.Parameter, parameterStructure);

        return ckMechanism;
    }

    /// <summary>
    /// Creates mechanism of given type with parameter copied from managed byte array to the newly allocated unmanaged memory
    /// </summary>
    /// <param name="mechanism">Mechanism type</param>
    /// <param name="parameter">Mechanism parameter</param>
    /// <returns>Mechanism of given type with specified parameter</returns>
    private static CK_MECHANISM _CreateMechanism(NativeCULong mechanism, byte[]? parameter)
    {
        CK_MECHANISM mech = new()
        {
            Mechanism = mechanism
        };

        if ((parameter != null) && (parameter.Length > 0))
        {
            mech.Parameter = UnmanagedMemory.Allocate(parameter.Length);
            UnmanagedMemory.Write(mech.Parameter, parameter);
            mech.ParameterLen = new NativeCULong((uint)parameter.Length);
        }
        else
        {
            mech.Parameter = IntPtr.Zero;
            mech.ParameterLen = new (0);
        }

        return mech;
    }
}