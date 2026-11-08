using System.Runtime.InteropServices;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// The derive mechanisms that put a base key's bytes in the key they make (<c>CKM_CONCATENATE_BASE_AND_DATA</c>,
/// <c>CKM_CONCATENATE_DATA_AND_BASE</c>, <c>CKM_XOR_BASE_AND_DATA</c>, <c>CKM_EXTRACT_KEY_FROM_KEY</c> and
/// <c>CKM_CONCATENATE_BASE_AND_KEY</c>) must not give back a protected key's bytes in a key that can be read.
/// PKCS#11 v3.2 §6.43 makes the derived key sensitive when a base key is, and not extractable when a base key is
/// not, whatever the template asks. The two rules are checked apart: a base key that is only sensitive, one that
/// is only unextractable, and one that is both.
/// </summary>
/// <remarks>
/// <para>
/// FreeHSM 2.2.0 to 2.5.1 applied the template instead (GHSA-4x45-2v79-28cj): a session asking for
/// <c>CKA_SENSITIVE = FALSE</c> and <c>CKA_EXTRACTABLE = TRUE</c> got a readable key holding the bytes of a key
/// it could not read, and XOR with zeros returns them unchanged. The library's <see cref="CryptoPolicy.Recommended"/>
/// refuses these mechanisms for that reason (Clulow's key-extraction attack); the case runs under
/// <see cref="CryptoPolicy.AllowInsecure"/> because what it checks is the token's own rule, which a caller that has
/// opted out still depends on.
/// </para>
/// <para>
/// Each case first derives the same way from keys in the clear and checks the value against the bytes the
/// mechanism defines. That shows the parameters are right, so a refusal of the protected derivation is the
/// token's rule at work, which the case accepts: no key is made, so none can be read.
/// </para>
/// <para>
/// The extraction and the one-rule-at-a-time protections follow pkcs11-check's byte-operation inheritance cases
/// (https://github.com/mingulov/pkcs11-check, <c>test_misc_kdf.py</c>, 0.3.0). HKDF is left out: its output is not
/// the base key's bytes, and §6.43's rule does not cover it.
/// </para>
/// </remarks>
internal static class BaseKeyProtectionTestCases
{
    private static readonly string[] Mechanisms =
    [
        "CONCATENATE_BASE_AND_DATA",
        "CONCATENATE_DATA_AND_BASE",
        "XOR_BASE_AND_DATA",
        "EXTRACT_KEY_FROM_KEY",
        "CONCATENATE_BASE_AND_KEY, protected base",
        "CONCATENATE_BASE_AND_KEY, protected second key",
    ];

    private const string Both = "sensitive and unextractable";
    private const string SensitiveOnly = "sensitive only";
    private const string UnextractableOnly = "unextractable only";

    /// <summary>Each derivation, with the protected key sensitive, unextractable, or both: "<c>mechanism; protection</c>".</summary>
    public static TheoryData<string> Derivations =>
        [.. from mechanism in Mechanisms from protection in (string[])[Both, SensitiveOnly, UnextractableOnly] select $"{mechanism}; {protection}"];

    // CKM_EXTRACT_KEY_FROM_KEY takes this many bytes from bit 0 of the base key (§6.43.8).
    private const int ExtractedLength = 8;

    private static readonly byte[] BaseValue = Convert.FromHexString("00112233445566778899aabbccddeeff");
    private static readonly byte[] SecondValue = Convert.FromHexString("0f0e0d0c0b0a09080706050403020100");

    // Zeros: XOR returns the base key's bytes unchanged, which is how the advisory read a sensitive key.
    private static readonly byte[] Data = new byte[16];

    internal static void Assert_KeyMadeFromAProtectedKey_KeepsItsProtection(IPkcs11Backend backend, string derivation)
    {
        string[] parts = derivation.Split("; ");
        CKM mechanism = parts[0] switch
        {
            "CONCATENATE_BASE_AND_DATA" => CKM.CKM_CONCATENATE_BASE_AND_DATA,
            "CONCATENATE_DATA_AND_BASE" => CKM.CKM_CONCATENATE_DATA_AND_BASE,
            "XOR_BASE_AND_DATA" => CKM.CKM_XOR_BASE_AND_DATA,
            "EXTRACT_KEY_FROM_KEY" => CKM.CKM_EXTRACT_KEY_FROM_KEY,
            _ => CKM.CKM_CONCATENATE_BASE_AND_KEY,
        };
        var protection = new Protection(Sensitive: parts[1] != UnextractableOnly, Unextractable: parts[1] != SensitiveOnly);
        backend.RequireMechanism(mechanism);
        bool protectSecond = parts[0].EndsWith("protected second key", StringComparison.Ordinal);

        using Pkcs11SessionCore session = TestKeys.OpenLoggedInSession(backend);
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        // What an attacker asks for: a generic secret it can read. The length is left to the mechanism.
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
        using var attrExtractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
        using var attrValueLen = new ObjectAttribute(CKA.CKA_VALUE_LEN, (ulong)ExtractedLength);
        List<ObjectAttribute> readable = [attrClass, attrType, attrToken, attrSensitive, attrExtractable];
        if (mechanism == CKM.CKM_EXTRACT_KEY_FROM_KEY)
            readable.Add(attrValueLen); // the length the extraction takes; the other mechanisms set their own
        var made = new List<ObjectHandle>();
        IntPtr data = Marshal.AllocHGlobal(Data.Length);
        try
        {
            Marshal.Copy(Data, 0, data, Data.Length);

            // The control: every key in the clear, so the derived value can be read and checked.
            ObjectHandle clearBase = Import(session, made, BaseValue, Protection.None);
            ObjectHandle clearSecond = Import(session, made, SecondValue, Protection.None);
            ObjectHandle control;
            try
            {
                control = session.DeriveKey(Parameters(mechanism, data, clearSecond), clearBase, readable);
            }
            catch (Pkcs11Exception ex)
            {
                Assert.Skip($"{derivation}: the module refuses the derivation from keys in the clear ({ex.ReturnValue}), so a refusal of the protected one shows nothing.");
                return;
            }
            made.Add(control);
            using (var value = session.GetAttributeValue(control, [CKA.CKA_VALUE]))
                Assert.Equal(Convert.ToHexString(Expected(mechanism)), Convert.ToHexString(value[0].GetValueAsByteArray()));

            ObjectHandle baseKey = protectSecond ? clearBase : Import(session, made, BaseValue, protection);
            ObjectHandle second = protectSecond ? Import(session, made, SecondValue, protection) : clearSecond;
            ObjectHandle derived;
            try
            {
                derived = session.DeriveKey(Parameters(mechanism, data, second), baseKey, readable);
            }
            catch (Pkcs11Exception)
            {
                return;
            }
            made.Add(derived);

            using var read = session.GetAttributeValue(derived, [CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE, CKA.CKA_VALUE]);
            Assert.True(read[2].CannotBeRead, $"{derivation}: the key made from a protected key can be read.");
            if (protection.Sensitive)
                Assert.True(read[0].GetValueAsBool(), $"{derivation}: the key made from a sensitive key is not CKA_SENSITIVE.");
            if (protection.Unextractable)
                Assert.False(read[1].GetValueAsBool(), $"{derivation}: the key made from an unextractable key is CKA_EXTRACTABLE.");
        }
        finally
        {
            foreach (ObjectHandle handle in made)
                session.DestroyObject(handle);
            Marshal.FreeHGlobal(data);
            TestKeys.LogoutIfRequired(backend, session);
        }
    }

    // How a key is protected: sensitive (CKA_SENSITIVE), unextractable (CKA_EXTRACTABLE false), both, or neither.
    private readonly record struct Protection(bool Sensitive, bool Unextractable)
    {
        public static Protection None => new(false, false);
    }

    // A generic secret that may derive, with the protection given.
    private static ObjectHandle Import(Pkcs11SessionCore session, List<ObjectHandle> made, byte[] value, Protection protection)
    {
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, protection.Sensitive);
        using var attrExtractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, !protection.Unextractable);
        using var attrDerive = new ObjectAttribute(CKA.CKA_DERIVE, true);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, value);
        ObjectHandle handle = session.CreateObject([attrClass, attrType, attrToken, attrSensitive, attrExtractable, attrDerive, attrValue]);
        made.Add(handle);
        return handle;
    }

    // CKM_CONCATENATE_BASE_AND_KEY takes the second key's handle, and CKM_EXTRACT_KEY_FROM_KEY the bit to start
    // from (a CK_EXTRACT_PARAMS, here 0); the others a CK_KEY_DERIVATION_STRING_DATA, whose pointer the caller
    // keeps valid until the call returns.
    private static Mechanism Parameters(CKM mechanism, IntPtr data, ObjectHandle second)
    {
        if (mechanism == CKM.CKM_CONCATENATE_BASE_AND_KEY)
            return new Mechanism(mechanism, NativeULong(second.ObjectId));
        if (mechanism == CKM.CKM_EXTRACT_KEY_FROM_KEY)
            return new Mechanism(mechanism, NativeULong(0));

        var parameter = new CK_KEY_DERIVATION_STRING_DATA { Data = data, Len = (NativeCULong)(ulong)Data.Length };
        int size = Pkcs11Marshal.SizeOf<CK_KEY_DERIVATION_STRING_DATA>();
        IntPtr block = Marshal.AllocHGlobal(size);
        try
        {
            Pkcs11Marshal.WriteStructure(block, in parameter);
            byte[] raw = new byte[size];
            Marshal.Copy(block, raw, 0, size);
            return new Mechanism(mechanism, raw);
        }
        finally { Marshal.FreeHGlobal(block); }
    }

    private static byte[] NativeULong(ulong value)
    {
        byte[] bytes = new byte[UnmanagedMemory.NativeULongSize];
        if (bytes.Length == sizeof(ulong))
            BitConverter.TryWriteBytes(bytes, value);
        else
            BitConverter.TryWriteBytes(bytes, checked((uint)value));
        return bytes;
    }

    // §6.43: the base key's bytes then the data, the data then the base, their XOR, the base's first bytes, or the
    // base then the second key.
    private static byte[] Expected(CKM mechanism) => mechanism switch
    {
        CKM.CKM_CONCATENATE_BASE_AND_DATA => [.. BaseValue, .. Data],
        CKM.CKM_CONCATENATE_DATA_AND_BASE => [.. Data, .. BaseValue],
        CKM.CKM_XOR_BASE_AND_DATA => [.. BaseValue.Zip(Data, (b, d) => (byte)(b ^ d))],
        CKM.CKM_EXTRACT_KEY_FROM_KEY => BaseValue[..ExtractedLength],
        _ => [.. BaseValue, .. SecondValue],
    };
}
