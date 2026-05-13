namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>
/// Interface for mechanism parameters
/// </summary>
public interface IMechanismParams : IDisposable
{
    /// <summary>
    /// Returns managed object that can be marshaled to an unmanaged block of memory
    /// </summary>
    /// <returns>A managed object holding the data to be marshaled. This object must be an instance of a formatted class.</returns>
    object ToMarshalableStructure();
}