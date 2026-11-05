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
/// <c>CKM_CONCATENATE_DATA_AND_BASE</c>, <c>CKM_XOR_BASE_AND_DATA</c> and <c>CKM_CONCATENATE_BASE_AND_KEY</c>)
/// must not give back a protected key's bytes in a key that can be read. PKCS#11 v3.2 §6.43 makes the derived
/// key sensitive when a base key is, and not extractable when a base key is not, whatever the template asks.
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
/// </remarks>
internal static class BaseKeyProtectionTestCases
{
    public static TheoryData<string> Derivations =>
    [
        "CONCATENATE_BASE_AND_DATA",
        "CONCATENATE_DATA_AND_BASE",
        "XOR_BASE_AND_DATA",
        "CONCATENATE_BASE_AND_KEY, protected base",
        "CONCATENATE_BASE_AND_KEY, protected second key",
    ];

    private static readonly byte[] BaseValue = Convert.FromHexString("00112233445566778899aabbccddeeff");
    private static readonly byte[] SecondValue = Convert.FromHexString("0f0e0d0c0b0a09080706050403020100");

    // Zeros: XOR returns the base key's bytes unchanged, which is how the advisory read a sensitive key.
    private static readonly byte[] Data = new byte[16];

    internal static void Assert_KeyMadeFromAProtectedKey_KeepsItsProtection(IPkcs11Backend backend, string derivation)
    {
        CKM mechanism = derivation switch
        {
            "CONCATENATE_BASE_AND_DATA" => CKM.CKM_CONCATENATE_BASE_AND_DATA,
            "CONCATENATE_DATA_AND_BASE" => CKM.CKM_CONCATENATE_DATA_AND_BASE,
            "XOR_BASE_AND_DATA" => CKM.CKM_XOR_BASE_AND_DATA,
            _ => CKM.CKM_CONCATENATE_BASE_AND_KEY,
        };
        backend.RequireMechanism(mechanism);
        bool protectSecond = derivation.EndsWith("protected second key", StringComparison.Ordinal);

        using Pkcs11SessionCore session = TestKeys.OpenLoggedInSession(backend);
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        // What an attacker asks for: a generic secret it can read. The length is left to the mechanism.
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
        using var attrExtractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
        List<ObjectAttribute> readable = [attrClass, attrType, attrToken, attrSensitive, attrExtractable];
        var made = new List<ObjectHandle>();
        IntPtr data = Marshal.AllocHGlobal(Data.Length);
        try
        {
            Marshal.Copy(Data, 0, data, Data.Length);

            // The control: every key in the clear, so the derived value can be read and checked.
            ObjectHandle clearBase = Import(session, made, BaseValue, isProtected: false);
            ObjectHandle clearSecond = Import(session, made, SecondValue, isProtected: false);
            ObjectHandle control = session.DeriveKey(Parameters(mechanism, data, clearSecond), clearBase, readable);
            made.Add(control);
            using (var value = session.GetAttributeValue(control, [CKA.CKA_VALUE]))
                Assert.Equal(Convert.ToHexString(Expected(mechanism)), Convert.ToHexString(value[0].GetValueAsByteArray()));

            ObjectHandle baseKey = protectSecond ? clearBase : Import(session, made, BaseValue, isProtected: true);
            ObjectHandle second = protectSecond ? Import(session, made, SecondValue, isProtected: true) : clearSecond;
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
            Assert.True(read[2].CannotBeRead, $"{derivation}: the key made from a sensitive, unextractable key can be read.");
            Assert.True(read[0].GetValueAsBool(), $"{derivation}: the key made from a sensitive key is not CKA_SENSITIVE.");
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

    // A generic secret that may derive; protected is sensitive and unextractable, the clear one neither.
    private static ObjectHandle Import(Pkcs11SessionCore session, List<ObjectHandle> made, byte[] value, bool isProtected)
    {
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, isProtected);
        using var attrExtractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, !isProtected);
        using var attrDerive = new ObjectAttribute(CKA.CKA_DERIVE, true);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, value);
        ObjectHandle handle = session.CreateObject([attrClass, attrType, attrToken, attrSensitive, attrExtractable, attrDerive, attrValue]);
        made.Add(handle);
        return handle;
    }

    // CKM_CONCATENATE_BASE_AND_KEY takes the second key's handle; the others a CK_KEY_DERIVATION_STRING_DATA,
    // whose pointer the caller keeps valid until the call returns.
    private static Mechanism Parameters(CKM mechanism, IntPtr data, ObjectHandle second)
    {
        if (mechanism == CKM.CKM_CONCATENATE_BASE_AND_KEY)
        {
            byte[] handle = new byte[UnmanagedMemory.NativeULongSize];
            if (handle.Length == sizeof(ulong))
                BitConverter.TryWriteBytes(handle, second.ObjectId);
            else
                BitConverter.TryWriteBytes(handle, checked((uint)second.ObjectId));
            return new Mechanism(mechanism, handle);
        }

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

    // §6.43: the base key's bytes then the data, the data then the base, their XOR, or the base then the second key.
    private static byte[] Expected(CKM mechanism) => mechanism switch
    {
        CKM.CKM_CONCATENATE_BASE_AND_DATA => [.. BaseValue, .. Data],
        CKM.CKM_CONCATENATE_DATA_AND_BASE => [.. Data, .. BaseValue],
        CKM.CKM_XOR_BASE_AND_DATA => [.. BaseValue.Zip(Data, (b, d) => (byte)(b ^ d))],
        _ => [.. BaseValue, .. SecondValue],
    };
}
