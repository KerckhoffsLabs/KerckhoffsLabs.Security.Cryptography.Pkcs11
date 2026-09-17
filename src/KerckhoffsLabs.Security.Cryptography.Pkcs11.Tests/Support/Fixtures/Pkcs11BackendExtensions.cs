using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

internal static class Pkcs11BackendExtensions
{
    /// <summary>
    /// Skips the test when the backend does not advertise <paramref name="mechanism"/> in its
    /// <c>C_GetMechanismList</c>. Lets one shared test case run on every backend that supports the
    /// mechanism and skip cleanly on those that do not — e.g. a v2.40 SoftHSM 2.5 that predates
    /// EdDSA, rather than failing with <c>CKR_MECHANISM_INVALID</c>.
    /// </summary>
    internal static void RequireMechanism(this IPkcs11Backend backend, CKM mechanism)
    {
        if (!backend.Supports(mechanism))
            Assert.Skip($"Backend does not advertise {mechanism}.");
    }

    /// <summary>
    /// Skips the test unless the backend's <c>CKM_ML_KEM_KEY_PAIR_GEN</c> mechanism info reports a
    /// min/max key-size range (in encapsulation-key bytes) covering <paramref name="encapsulationKeySizeInBytes"/>.
    /// ML-KEM has exactly three discrete parameter sets, so this range doubles as a per-parameter-set
    /// capability check — e.g. NSS only added ML-KEM-512 support in 3.129, so its 3.128 mechanism info
    /// would report a min above the 512 key size and this skips cleanly instead of failing with
    /// <c>CKR_ATTRIBUTE_VALUE_INVALID</c>. <c>CKM_ML_KEM</c> itself is checked first via
    /// <see cref="RequireMechanism"/>.
    /// </summary>
    internal static void RequireMlKemParameterSet(this IPkcs11Backend backend, int encapsulationKeySizeInBytes)
    {
        backend.RequireMechanism(CKM.CKM_ML_KEM);
        Pkcs11Slot slot = backend.Library.GetSlotList().First(s => s.SlotId.Value == (ulong)backend.SlotId);
        MechanismInfo info = slot.GetMechanismInfo(CKM.CKM_ML_KEM_KEY_PAIR_GEN);
        if ((ulong)encapsulationKeySizeInBytes < info.MinKeySize || (ulong)encapsulationKeySizeInBytes > info.MaxKeySize)
            Assert.Skip($"Backend's CKM_ML_KEM_KEY_PAIR_GEN key-size range [{info.MinKeySize}, {info.MaxKeySize}] " +
                $"does not cover a {encapsulationKeySizeInBytes}-byte encapsulation key.");
    }
}
