using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Mixes additional seed material into the token's random number generator
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="seed">The seed material</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_ACTIVE, CKR_RANDOM_SEED_NOT_SUPPORTED, CKR_RANDOM_NO_RNG, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_SeedRandom(NativeCULong session, ReadOnlySpan<byte> seed)
    {
        using ModuleCall call = EnterModule();
        var seedRandom = call.Functions.C_SeedRandom;
        if (seedRandom is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* seedPtr = seed)
            return seedRandom(session, seedPtr, (NativeCULong)seed.Length).ToCKR();
    }

    /// <summary>
    /// Generates random or pseudo-random data
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="randomData">Location that receives the random data</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_ACTIVE, CKR_RANDOM_NO_RNG, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_GenerateRandom(NativeCULong session, Span<byte> randomData)
    {
        using ModuleCall call = EnterModule();
        var generateRandom = call.Functions.C_GenerateRandom;
        if (generateRandom is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* outPtr = &NonNullPinnable(randomData))
            return generateRandom(session, outPtr, (NativeCULong)randomData.Length).ToCKR();
    }
}
