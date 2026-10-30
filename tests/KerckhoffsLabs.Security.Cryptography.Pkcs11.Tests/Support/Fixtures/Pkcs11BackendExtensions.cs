using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

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
    /// Skips the test when the backend does not advertise every mechanism in <paramref name="mechanisms"/>,
    /// reporting all missing ones in one message rather than stopping at the first. For a case that needs
    /// several mechanisms together (e.g. key generation plus a signing mechanism).
    /// </summary>
    internal static void RequireMechanisms(this IPkcs11Backend backend, params CKM[] mechanisms)
    {
        CKM[] missing = [.. mechanisms.Where(m => !backend.Supports(m))];
        if (missing.Length > 0)
            Assert.Skip($"Backend does not advertise {string.Join(", ", missing)}.");
    }

    /// <summary>
    /// Skips the test unless the backend advertises <paramref name="mechanism"/> and its
    /// <c>C_GetMechanismInfo</c> flags include every capability <paramref name="hasFlags"/> checks. For a
    /// mechanism a token lists for some operations only, e.g. <c>CKM_AES_KEY_WRAP_KWP</c> for
    /// <c>C_WrapKey</c> but not <c>C_Encrypt</c>.
    /// </summary>
    internal static void RequireMechanismFlags(this IPkcs11Backend backend, CKM mechanism, Func<MechanismFlags, bool> hasFlags, string operation)
    {
        backend.RequireMechanism(mechanism);
        Pkcs11Slot slot = backend.Library.GetSlotList().First(s => s.SlotId.Value == (ulong)backend.SlotId);
        if (!hasFlags(slot.GetMechanismInfo(mechanism).MechanismFlags))
            Assert.Skip($"Backend advertises {mechanism} without {operation}.");
    }

    /// <summary>
    /// Runs <paramref name="create"/>, which makes a key of <paramref name="keySizeInBits"/> bits for
    /// <paramref name="mechanism"/>, and skips the test when the token refuses it and the size is outside the
    /// key-size range its <c>C_GetMechanismInfo</c> reports: the modulus for the RSA mechanisms, the field size
    /// for the EC ones (PKCS#11 v3.2 §6.1, §6.3). PKCS#11 has no per-curve capability, and tokens refuse a
    /// curve or modulus they lack with different codes; the range is the closest a token comes to saying
    /// what it has. A key the token makes runs whatever its range says (BouncyHsm reports ECDSA from 192
    /// bits but handles secp160r1), and a refusal inside the range still fails. A range of [0, 0] reports
    /// nothing, so it skips nothing, as for <see cref="RequireMlKemParameterSet"/>.
    /// </summary>
    internal static T SkipIfRefusedOutsideKeySize<T>(this IPkcs11Backend backend, CKM mechanism, int keySizeInBits, Func<T> create)
    {
        try
        {
            return create();
        }
        catch (Pkcs11Exception ex) when (OutsideKeySize(backend, mechanism, keySizeInBits) is { } range)
        {
            Assert.Skip($"Backend refused a {keySizeInBits}-bit key ({ex.ReturnValue}) outside its {mechanism} " +
                $"key-size range {range}.");
            throw; // unreachable: Assert.Skip throws
        }
    }

    // The token's key-size range for the mechanism, when it reports one that leaves the size out.
    private static string? OutsideKeySize(IPkcs11Backend backend, CKM mechanism, int keySizeInBits)
    {
        Pkcs11Slot slot = backend.Library.GetSlotList().First(s => s.SlotId.Value == (ulong)backend.SlotId);
        MechanismInfo info = slot.GetMechanismInfo(mechanism);
        bool outside = info.MaxKeySize != 0 &&
            ((ulong)keySizeInBits < info.MinKeySize || (ulong)keySizeInBits > info.MaxKeySize);
        return outside ? $"[{info.MinKeySize}, {info.MaxKeySize}]" : null;
    }

    /// <summary>
    /// Skips the test unless the backend's <c>CKM_ML_KEM_KEY_PAIR_GEN</c> mechanism info reports a
    /// min/max key-size range (in encapsulation-key bytes) covering <paramref name="encapsulationKeySizeInBytes"/>.
    /// ML-KEM has exactly three discrete parameter sets, so this range doubles as a per-parameter-set
    /// capability check — e.g. NSS only added ML-KEM-512 support in 3.129, so its 3.128 mechanism info
    /// would report a min above the 512 key size and this skips cleanly instead of failing with
    /// <c>CKR_ATTRIBUTE_VALUE_INVALID</c>. <c>CKM_ML_KEM</c> itself is checked first via
    /// <see cref="RequireMechanism"/>. A range of [0, 0] reports nothing (FreeHSM leaves both fields zero for
    /// all three parameter sets), so it skips nothing.
    /// </summary>
    internal static void RequireMlKemParameterSet(this IPkcs11Backend backend, int encapsulationKeySizeInBytes)
    {
        backend.RequireMechanism(CKM.CKM_ML_KEM);
        Pkcs11Slot slot = backend.Library.GetSlotList().First(s => s.SlotId.Value == (ulong)backend.SlotId);
        MechanismInfo info = slot.GetMechanismInfo(CKM.CKM_ML_KEM_KEY_PAIR_GEN);
        if (info.MaxKeySize == 0)
            return;
        if ((ulong)encapsulationKeySizeInBytes < info.MinKeySize || (ulong)encapsulationKeySizeInBytes > info.MaxKeySize)
            Assert.Skip($"Backend's CKM_ML_KEM_KEY_PAIR_GEN key-size range [{info.MinKeySize}, {info.MaxKeySize}] " +
                $"does not cover a {encapsulationKeySizeInBytes}-byte encapsulation key.");
    }
}
