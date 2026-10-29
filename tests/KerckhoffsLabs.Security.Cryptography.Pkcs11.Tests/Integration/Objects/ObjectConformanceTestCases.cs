using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Objects;

/// <summary>
/// The object and attribute rules of PKCS#11 v3.2 §4 and §5.7, checked on every real backend through the
/// session core: attributes that can be changed and those that cannot, the one-way key flags, the
/// <c>CKA_MODIFIABLE</c>/<c>CKA_COPYABLE</c>/<c>CKA_DESTROYABLE</c> controls, what a copy keeps, the
/// provenance attributes a module derives, a read that mixes readable and unreadable attributes, values of
/// unusual sizes and types, and malformed templates.
/// </summary>
/// <remarks>
/// Every object is a session object (<c>CKA_TOKEN = FALSE</c>) unless the case says otherwise, so whatever a
/// failed case leaves behind goes with its session. A refusal is any <see cref="Pkcs11Exception"/>; where a
/// backend answers with a code other than the one PKCS#11 names, its wrapper says so.
/// </remarks>
internal static class ObjectConformanceTestCases
{
    private static void WithSession(IPkcs11Backend backend, Action<Pkcs11SessionCore> body)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try { body(session); }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    private static ObjectHandle CreateDataObject(Pkcs11SessionCore session, string label, byte[] value, params ObjectAttribute[] extra)
    {
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, value);
        return session.CreateObject([attrClass, attrToken, attrLabel, attrValue, .. extra]);
    }

    // A generated AES-256 session key, sensitive and not extractable, with the usage the case needs.
    private static ObjectHandle GenerateAesKey(Pkcs11SessionCore session, params ObjectAttribute[] extra)
    {
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrValueLen = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
        using var attrEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var attrDecrypt = new ObjectAttribute(CKA.CKA_DECRYPT, true);
        using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var attrExtractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, false);
        List<ObjectAttribute> template = [attrClass, attrKeyType, attrToken, attrValueLen, attrEncrypt, attrDecrypt, attrSensitive, attrExtractable];
        foreach (ObjectAttribute attribute in extra)
        {
            template.RemoveAll(a => a.Type == attribute.Type);
            template.Add(attribute);
        }
        return session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template);
    }

    private static bool ReadBool(Pkcs11SessionCore session, ObjectHandle handle, CKA attribute)
    {
        using var read = session.GetAttributeValue(handle, [attribute]);
        return read[0].GetValueAsBool();
    }

    private static byte[] Read(Pkcs11SessionCore session, ObjectHandle handle, CKA attribute)
    {
        using var read = session.GetAttributeValue(handle, [attribute]);
        return read[0].GetValueAsByteArray();
    }

    private static void Set(Pkcs11SessionCore session, ObjectHandle handle, ObjectAttribute attribute)
        => session.SetAttributeValue(handle, [attribute]);

    // === C_SetAttributeValue ===================================================

    // CKA_LABEL and CKA_ID can be changed on a key that is CKA_MODIFIABLE (§4.4), and read back as set.
    internal static void Assert_SetAttributeValue_LabelAndId_RoundTrip(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        WithSession(backend, session =>
        {
            using var before = new ObjectAttribute(CKA.CKA_LABEL, "kl-before");
            ObjectHandle data = GenerateAesKey(session, before);
            try
            {
                using var label = new ObjectAttribute(CKA.CKA_LABEL, "kl-after");
                using var id = new ObjectAttribute(CKA.CKA_ID, (byte[])[0xDE, 0xAD, 0xBE, 0xEF]);
                session.SetAttributeValue(data, [label, id]);

                using var read = session.GetAttributeValue(data, [CKA.CKA_LABEL, CKA.CKA_ID]);
                Assert.Equal("kl-after", read[0].GetValueAsString());
                Assert.Equal([0xDE, 0xAD, 0xBE, 0xEF], read[1].GetValueAsByteArray());
            }
            finally { session.DestroyObject(data); }
        });
    }

    public static TheoryData<CKA> ReadOnlyKeyAttributes =>
    [
        CKA.CKA_CLASS, CKA.CKA_KEY_TYPE, CKA.CKA_LOCAL, CKA.CKA_ALWAYS_SENSITIVE, CKA.CKA_NEVER_EXTRACTABLE, CKA.CKA_KEY_GEN_MECHANISM, CKA.CKA_VALUE_LEN,
        CKA.CKA_TOKEN, CKA.CKA_PRIVATE, CKA.CKA_MODIFIABLE,
    ];

    // An attribute a module derives, or that fixes what the object is, cannot be set after creation
    // (§4.1, Table 7 footnote 4): the call is refused with CKR_ATTRIBUTE_READ_ONLY and the attribute reads as
    // it did. CKA_TOKEN, CKA_PRIVATE and CKA_MODIFIABLE change only in a copy (§4.4: "Only the CKA_LABEL
    // attribute can be modified after the object is created"; §4.1.3). ignored records a backend that returns
    // CKR_OK and leaves the attribute as it was.
    internal static void Assert_SetAttributeValue_ReadOnlyKeyAttribute_IsRefused(IPkcs11Backend backend, CKA attribute, bool ignored = false)
    {
        backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        WithSession(backend, session =>
        {
            ObjectHandle key = GenerateAesKey(session);
            try
            {
                using var before = session.GetAttributeValue(key, [attribute]);
                if (before[0].CannotBeRead)
                    Assert.Skip($"The backend does not report {attribute}.");
                byte[] original = before[0].GetValueAsByteArray();

                using ObjectAttribute changed = attribute switch
                {
                    CKA.CKA_CLASS => new(attribute, CKO.CKO_DATA),
                    CKA.CKA_KEY_TYPE => new(attribute, CKK.CKK_GENERIC_SECRET),
                    CKA.CKA_KEY_GEN_MECHANISM => new(attribute, (ulong)CKM.CKM_DES3_KEY_GEN),
                    CKA.CKA_VALUE_LEN => new(attribute, 16UL),
                    _ => new(attribute, !before[0].GetValueAsBool()),
                };
                if (ignored)
                    Set(session, key, changed);
                else
                    Assert.ThrowsAny<Pkcs11Exception>(() => Set(session, key, changed));
                Assert.Equal(original, Read(session, key, attribute));
            }
            finally { session.DestroyObject(key); }
        });
    }

    public static TheoryData<CKA> OneWayFlags => [CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE];

    // CKA_SENSITIVE can go from FALSE to TRUE and never back, CKA_EXTRACTABLE from TRUE to FALSE and never back
    // (Table 10 footnotes 8 and 9). A module refuses the change back or ignores it; either way the flag stays.
    internal static void Assert_OneWayFlag_CannotBeUndone(IPkcs11Backend backend, CKA flag)
    {
        backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        WithSession(backend, session =>
        {
            ObjectHandle key = GenerateAesKey(session);
            try
            {
                bool protectedValue = flag == CKA.CKA_SENSITIVE;
                Assert.Equal(protectedValue, ReadBool(session, key, flag));
                using var undone = new ObjectAttribute(flag, !protectedValue);
                try { Set(session, key, undone); }
                catch (Pkcs11Exception) { /* refused, as the spec allows */ }
                Assert.Equal(protectedValue, ReadBool(session, key, flag));
            }
            finally { session.DestroyObject(key); }
        });
    }

    // === CKA_MODIFIABLE, CKA_COPYABLE, CKA_DESTROYABLE =========================

    // An object created CKA_MODIFIABLE = FALSE keeps its attributes: C_SetAttributeValue is refused (§4.4).
    internal static void Assert_UnmodifiableObject_RefusesChanges(IPkcs11Backend backend)
    {
        WithSession(backend, session =>
        {
            using var modifiable = new ObjectAttribute(CKA.CKA_MODIFIABLE, false);
            ObjectHandle data = CreateDataObject(session, "kl-fixed", [0x01], modifiable);
            try
            {
                Assert.False(ReadBool(session, data, CKA.CKA_MODIFIABLE));
                using var label = new ObjectAttribute(CKA.CKA_LABEL, "kl-changed");
                Assert.ThrowsAny<Pkcs11Exception>(() => Set(session, data, label));
                using var read = session.GetAttributeValue(data, [CKA.CKA_LABEL]);
                Assert.Equal("kl-fixed", read[0].GetValueAsString());
            }
            finally { session.DestroyObject(data); }
        });
    }

    // An object created CKA_COPYABLE = FALSE cannot be copied: C_CopyObject is CKR_ACTION_PROHIBITED (§4.4).
    internal static void Assert_UncopyableObject_RefusesCopies(IPkcs11Backend backend, CKR expected = CKR.CKR_ACTION_PROHIBITED)
    {
        WithSession(backend, session =>
        {
            using var copyable = new ObjectAttribute(CKA.CKA_COPYABLE, false);
            ObjectHandle data = CreateDataObject(session, "kl-uncopyable", [0x01], copyable);
            try
            {
                var ex = Assert.ThrowsAny<Pkcs11Exception>(() => session.CopyObject(data, []));
                Assert.Equal(expected, ex.ReturnValue);
            }
            finally { session.DestroyObject(data); }
        });
    }

    // An object created CKA_DESTROYABLE = FALSE survives C_DestroyObject, which is CKR_ACTION_PROHIBITED
    // (§4.4). A session object, so it goes when the case's session closes.
    internal static void Assert_UndestroyableObject_RefusesDestruction(IPkcs11Backend backend, CKR expected = CKR.CKR_ACTION_PROHIBITED)
    {
        WithSession(backend, session =>
        {
            string label = $"kl-undestroyable-{Guid.NewGuid():N}";
            using var destroyable = new ObjectAttribute(CKA.CKA_DESTROYABLE, false);
            ObjectHandle data = CreateDataObject(session, label, [0x01], destroyable);
            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => session.DestroyObject(data));
            Assert.Equal(expected, ex.ReturnValue);
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            Assert.Single(session.FindAllObjects([attrLabel]));
        });
    }

    // === C_CopyObject ==========================================================

    // A copy is a new object with the original's attributes and those the template changes (§5.7): a new
    // label, and the protection the original had. A copy cannot make the key extractable again; the module
    // refuses the template or the copy stays unextractable.
    internal static void Assert_CopyObject_KeepsTheProtection(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        WithSession(backend, session =>
        {
            using var label = new ObjectAttribute(CKA.CKA_LABEL, "kl-original");
            ObjectHandle key = GenerateAesKey(session, label);
            var copies = new List<ObjectHandle>();
            try
            {
                using var newLabel = new ObjectAttribute(CKA.CKA_LABEL, "kl-copy");
                ObjectHandle copy = session.CopyObject(key, [newLabel]);
                copies.Add(copy);
                Assert.NotEqual(key.ObjectId, copy.ObjectId);
                using (var read = session.GetAttributeValue(copy, [CKA.CKA_LABEL, CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE, CKA.CKA_KEY_TYPE]))
                {
                    Assert.Equal("kl-copy", read[0].GetValueAsString());
                    Assert.True(read[1].GetValueAsBool(), "The copy lost CKA_SENSITIVE.");
                    Assert.False(read[2].GetValueAsBool(), "The copy became extractable.");
                    Assert.Equal((ulong)CKK.CKK_AES, read[3].GetValueAsUlong());
                }
                using (var read = session.GetAttributeValue(key, [CKA.CKA_LABEL]))
                    Assert.Equal("kl-original", read[0].GetValueAsString());

                using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
                using var extractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
                try
                {
                    ObjectHandle weakened = session.CopyObject(key, [extractable]);
                    copies.Add(weakened);
                    Assert.False(ReadBool(session, weakened, CKA.CKA_EXTRACTABLE), "A copy made an unextractable key extractable.");
                }
                catch (Pkcs11Exception) { /* refused, as the spec allows */ }
            }
            finally
            {
                foreach (ObjectHandle copy in copies)
                    session.DestroyObject(copy);
                session.DestroyObject(key);
            }
        });
    }

    // === Provenance ============================================================

    // A module derives CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE and CKA_KEY_GEN_MECHANISM (§4.7): a key it
    // generated sensitive and unextractable has both flags TRUE and its generation mechanism; a key imported
    // with its value has both FALSE, and no generation mechanism (CK_UNAVAILABLE_INFORMATION).
    // reported names the provenance attributes the backend reports; importedNeverExtractable records a backend
    // that reports an imported, unextractable key as CKA_NEVER_EXTRACTABLE, importedKeyGenMechanism one that
    // reports a generation mechanism for it.
    internal static void Assert_ProvenanceAttributes_TellGeneratedFromImported(IPkcs11Backend backend, CKA[]? reported = null, bool importedNeverExtractable = false, ulong? importedKeyGenMechanism = null)
    {
        reported ??= [CKA.CKA_ALWAYS_SENSITIVE, CKA.CKA_NEVER_EXTRACTABLE, CKA.CKA_KEY_GEN_MECHANISM];
        backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        WithSession(backend, session =>
        {
            ObjectHandle generated = GenerateAesKey(session);
            ObjectHandle imported = TestKeys.CreateAes256Key(session, RandomNumberGenerator.GetBytes(32));
            try
            {
                // Only what the backend reports is checked; reported indicates which ones its wrapper expects.
                CKA[] provenance = [CKA.CKA_ALWAYS_SENSITIVE, CKA.CKA_NEVER_EXTRACTABLE, CKA.CKA_KEY_GEN_MECHANISM];
                using var gen = session.GetAttributeValue(generated, provenance);
                using var imp = session.GetAttributeValue(imported, provenance);
                Assert.Equal(reported, provenance.Where((_, i) => !gen[i].CannotBeRead).ToArray());
                if (!gen[0].CannotBeRead)
                {
                    Assert.True(gen[0].GetValueAsBool(), "A key generated sensitive is not CKA_ALWAYS_SENSITIVE.");
                    Assert.False(imp[0].GetValueAsBool(), "An imported key is CKA_ALWAYS_SENSITIVE.");
                }
                if (!gen[1].CannotBeRead)
                {
                    Assert.True(gen[1].GetValueAsBool(), "A key generated unextractable is not CKA_NEVER_EXTRACTABLE.");
                    Assert.Equal(importedNeverExtractable, imp[1].GetValueAsBool());
                }
                if (!gen[2].CannotBeRead)
                {
                    Assert.Equal((ulong)CKM.CKM_AES_KEY_GEN, gen[2].GetValueAsUlong());
                    Assert.Equal(importedKeyGenMechanism ?? CK.CK_UNAVAILABLE_INFORMATION, imp[2].GetValueAsUlong());
                }
            }
            finally
            {
                session.DestroyObject(imported);
                session.DestroyObject(generated);
            }
        });
    }

    // The library's AES generators give no key CKA_DERIVE: a key that can derive other keys passes its value
    // into every key derived from it, and neither a data key nor a key-encryption key needs it. (The EC
    // generator grants it to the private key on purpose: its keys sign and agree, and ECDH is a derive.)
    internal static void Assert_LibraryGenerators_NeverGrantDerive(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        using var session = backend.OpenSession();
        using var aes = session.GenerateAesKey(bitLength: 256);
        using var kek = session.GenerateAesKeyEncryptionKey(bitLength: 256);
        foreach (var (name, handle) in new[] { ("AES key", aes.PrivateHandle), ("AES KEK", kek.PrivateHandle) })
        {
            using var read = session.Core.GetAttributeValue(handle, [CKA.CKA_DERIVE]);
            Assert.False(read[0].GetValueAsBool(), $"The library's {name} has CKA_DERIVE.");
        }
    }

    // === Reads =================================================================

    // One C_GetAttributeValue for a sensitive value, an attribute the class does not have, and two readable
    // attributes: the module marks the first two unavailable and still fills the others (§5.7), and the
    // library returns all four, the first two as unreadable, rather than failing the read.
    internal static void Assert_MixedRead_FillsTheReadableAttributes(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        WithSession(backend, session =>
        {
            using var label = new ObjectAttribute(CKA.CKA_LABEL, "kl-mixed-read");
            ObjectHandle key = GenerateAesKey(session, label);
            try
            {
                using var read = session.GetAttributeValue(key, [CKA.CKA_VALUE, CKA.CKA_MODULUS, CKA.CKA_LABEL, CKA.CKA_KEY_TYPE]);
                Assert.True(read[0].CannotBeRead, "A sensitive key's CKA_VALUE was read.");
                Assert.True(read[1].CannotBeRead, "An AES key reported a CKA_MODULUS.");
                Assert.Equal("kl-mixed-read", read[2].GetValueAsString());
                Assert.Equal((ulong)CKK.CKK_AES, read[3].GetValueAsUlong());
            }
            finally { session.DestroyObject(key); }
        });
    }

    public static TheoryData<string> SensitivePrivateKeyTypes => ["RSA", "EC", "ML-DSA", "ML-KEM"];

    // A private key generated CKA_SENSITIVE = TRUE does not reveal its secret parts (footnote 7 of the RSA, EC,
    // ML-DSA and ML-KEM private key tables, §6.1.3, §6.3.4, §6.67.3, §6.68.3). Through the raw call, so that the
    // module's own answer is seen: C_GetAttributeValue of each part alone, with pValue NULL and with a buffer
    // large enough, answers CKR_ATTRIBUTE_SENSITIVE, sets ulValueLen to CK_UNAVAILABLE_INFORMATION and writes
    // nothing into the buffer (§5.7.5, case 1, which comes before the NULL and the buffer cases). The parts the
    // tables do not require a key to have (the RSA CRT values, the ML-DSA and ML-KEM seed) may instead be
    // CKR_ATTRIBUTE_TYPE_INVALID, the answer for an attribute the key does not hold (case 2), with the same
    // length. Then one read of every secret part, an attribute the key type does not have, CKA_LABEL and
    // CKA_KEY_TYPE answers one of those two codes, marks the first ones unavailable and still fills the last two.
    internal static void Assert_SensitivePrivateKey_HidesItsSecretParts(IPkcs11Backend backend, string keyType)
    {
        (CKM generation, CKK type, CKA[] required, CKA[] optional, CKA foreign) = keyType switch
        {
            "RSA" => (CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, CKK.CKK_RSA, (CKA[])[CKA.CKA_PRIVATE_EXPONENT],
                (CKA[])[CKA.CKA_PRIME_1, CKA.CKA_PRIME_2, CKA.CKA_EXPONENT_1, CKA.CKA_EXPONENT_2, CKA.CKA_COEFFICIENT], CKA.CKA_EC_POINT),
            "EC" => (CKM.CKM_EC_KEY_PAIR_GEN, CKK.CKK_EC, [CKA.CKA_VALUE], [], CKA.CKA_MODULUS),
            "ML-DSA" => (CKM.CKM_ML_DSA_KEY_PAIR_GEN, CKK.CKK_ML_DSA, [CKA.CKA_VALUE], [CKA.CKA_SEED], CKA.CKA_MODULUS),
            _ => (CKM.CKM_ML_KEM_KEY_PAIR_GEN, CKK.CKK_ML_KEM, [CKA.CKA_VALUE], [CKA.CKA_SEED], CKA.CKA_MODULUS),
        };
        backend.RequireMechanism(generation);
        if (keyType == "ML-KEM")
            backend.RequireMlKemParameterSet(1184); // ML-KEM-768

        WithSession(backend, session =>
        {
            string label = $"kl-sensitive-{Guid.NewGuid():N}";
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
            using var attrPublicUse = new ObjectAttribute(keyType == "ML-KEM" ? CKA.CKA_ENCAPSULATE : CKA.CKA_VERIFY, true);
            using var attrPrivateUse = new ObjectAttribute(keyType == "ML-KEM" ? CKA.CKA_DECAPSULATE : CKA.CKA_SIGN, true);
            using ObjectAttribute attrKeyParameter = keyType switch
            {
                "RSA" => new(CKA.CKA_MODULUS_BITS, 2048UL),
                "EC" => new(CKA.CKA_EC_PARAMS, TestKeys.EcP256Oid),
                "ML-DSA" => new(CKA.CKA_PARAMETER_SET, (ulong)CkpMlDsa.CKP_ML_DSA_44),
                _ => new(CKA.CKA_PARAMETER_SET, (ulong)CkpMlKem.CKP_ML_KEM_768),
            };
            session.GenerateKeyPair(new Mechanism(generation),
                [attrToken, attrLabel, attrPublicUse, attrKeyParameter],
                [attrToken, attrLabel, attrPrivateUse, attrSensitive], out ObjectHandle publicKey, out ObjectHandle privateKey);
            try
            {
                Assert.True(ReadBool(session, privateKey, CKA.CKA_SENSITIVE), "The private key was generated with CKA_SENSITIVE = FALSE.");
                LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
                var sid = (NativeCULong)session.SessionId;
                var key = (NativeCULong)privateKey.ObjectId;
                const int bufferLength = 8192; // above every secret part here: an ML-DSA-44 sk is 2560 bytes
                IntPtr buffer = Marshal.AllocHGlobal(bufferLength);
                try
                {
                    foreach (CKA part in required.Concat(optional))
                    {
                        CKR[] accepted = required.Contains(part) ? [CKR.CKR_ATTRIBUTE_SENSITIVE] : [CKR.CKR_ATTRIBUTE_SENSITIVE, CKR.CKR_ATTRIBUTE_TYPE_INVALID];
                        CK_ATTRIBUTE[] lengthQuery = [new CK_ATTRIBUTE { type = (NativeCULong)(ulong)part }];
                        CKR rv = lowLevel.C_GetAttributeValue(sid, key, lengthQuery);
                        Assert.True(accepted.Contains(rv), $"{keyType} {part}, pValue NULL: C_GetAttributeValue returned {rv}.");
                        Assert.True((ulong)lengthQuery[0].valueLen == CK.CK_UNAVAILABLE_INFORMATION,
                            $"{keyType} {part}, pValue NULL: ulValueLen is {(ulong)lengthQuery[0].valueLen}, not CK_UNAVAILABLE_INFORMATION.");

                        Marshal.Copy(new byte[bufferLength], 0, buffer, bufferLength);
                        CK_ATTRIBUTE[] read = [new CK_ATTRIBUTE { type = (NativeCULong)(ulong)part, value = buffer, valueLen = (NativeCULong)(ulong)bufferLength }];
                        rv = lowLevel.C_GetAttributeValue(sid, key, read);
                        Assert.True(accepted.Contains(rv), $"{keyType} {part}, with a buffer: C_GetAttributeValue returned {rv}.");
                        Assert.True((ulong)read[0].valueLen == CK.CK_UNAVAILABLE_INFORMATION,
                            $"{keyType} {part}, with a buffer: ulValueLen is {(ulong)read[0].valueLen}, not CK_UNAVAILABLE_INFORMATION.");
                        byte[] written = new byte[bufferLength];
                        Marshal.Copy(buffer, written, 0, bufferLength);
                        Assert.True(written.All(b => b == 0), $"{keyType} {part}: the module wrote into the buffer of a value it may not reveal.");
                    }

                    // The mixed read: each attribute in its own slice of the buffer.
                    CKA[] hidden = [.. required, .. optional, foreign];
                    const int slice = 512;
                    int sliceCount = hidden.Length + 2;
                    Assert.True(sliceCount * slice <= bufferLength);
                    CK_ATTRIBUTE[] mixed = [.. hidden.Append(CKA.CKA_LABEL).Append(CKA.CKA_KEY_TYPE).Select((attribute, i) => new CK_ATTRIBUTE
                    {
                        type = (NativeCULong)(ulong)attribute,
                        value = buffer + (i * slice),
                        valueLen = (NativeCULong)(ulong)slice,
                    })];
                    CKR mixedRv = lowLevel.C_GetAttributeValue(sid, key, mixed);
                    Assert.True(mixedRv is CKR.CKR_ATTRIBUTE_SENSITIVE or CKR.CKR_ATTRIBUTE_TYPE_INVALID, $"{keyType} mixed read: C_GetAttributeValue returned {mixedRv}.");
                    for (int i = 0; i < hidden.Length; i++)
                    {
                        Assert.True((ulong)mixed[i].valueLen == CK.CK_UNAVAILABLE_INFORMATION,
                            $"{keyType} mixed read: {hidden[i]}'s ulValueLen is {(ulong)mixed[i].valueLen}, not CK_UNAVAILABLE_INFORMATION.");
                    }
                    byte[] labelBytes = System.Text.Encoding.UTF8.GetBytes(label);
                    Assert.True((ulong)mixed[^2].valueLen == (ulong)labelBytes.Length, $"{keyType} mixed read: CKA_LABEL's ulValueLen is {(ulong)mixed[^2].valueLen}.");
                    byte[] readLabel = new byte[labelBytes.Length];
                    Marshal.Copy(mixed[^2].value, readLabel, 0, readLabel.Length);
                    Assert.Equal(labelBytes, readLabel);
                    int ulongSize = Unsafe.SizeOf<NativeCULong>();
                    Assert.True((ulong)mixed[^1].valueLen == (ulong)ulongSize, $"{keyType} mixed read: CKA_KEY_TYPE's ulValueLen is {(ulong)mixed[^1].valueLen}.");
                    byte[] readType = new byte[ulongSize];
                    Marshal.Copy(mixed[^1].value, readType, 0, ulongSize);
                    Assert.Equal((ulong)type, (ulong)MemoryMarshal.Read<NativeCULong>(readType));
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            finally
            {
                session.DestroyObject(privateKey);
                session.DestroyObject(publicKey);
            }
        });
    }

    public static TheoryData<int> DataValueLengths => [0, 1, 4096, 65_536, 1 << 20];

    // A data object's CKA_VALUE of any length, empty to 1 MiB, reads back byte for byte.
    // maxLength records a backend that refuses a longer value at creation with CKR_ATTRIBUTE_VALUE_INVALID.
    internal static void Assert_DataValue_RoundTrips(IPkcs11Backend backend, int length, int maxLength = int.MaxValue)
    {
        WithSession(backend, session =>
        {
            if (length > maxLength)
            {
                var ex = Assert.ThrowsAny<Pkcs11Exception>(() => CreateDataObject(session, "kl-large-value", new byte[length]));
                Assert.Equal(CKR.CKR_ATTRIBUTE_VALUE_INVALID, ex.ReturnValue);
                return;
            }
            byte[] value = RandomNumberGenerator.GetBytes(length);
            ObjectHandle data = CreateDataObject(session, "kl-large-value", value);
            try
            {
                using var read = session.GetAttributeValue(data, [CKA.CKA_VALUE]);
                Assert.True(value.AsSpan().SequenceEqual(read[0].GetValueAsByteArray()), $"A {length}-byte CKA_VALUE did not read back.");
            }
            finally { session.DestroyObject(data); }
        });
    }

    // CKA_APPLICATION, a UTF-8 string, round-trips and is searchable.
    internal static void Assert_Application_RoundTripsAndIsSearchable(IPkcs11Backend backend)
    {
        WithSession(backend, session =>
        {
            string application = $"kl-app-{Guid.NewGuid():N}";
            using var attrApplication = new ObjectAttribute(CKA.CKA_APPLICATION, application);
            ObjectHandle data = CreateDataObject(session, "kl-application", [0x01], attrApplication);
            try
            {
                using (var read = session.GetAttributeValue(data, [CKA.CKA_APPLICATION]))
                    Assert.Equal(application, read[0].GetValueAsString());
                using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
                Assert.Equal([data.ObjectId], session.FindAllObjects([attrClass, attrApplication]).Select(h => h.ObjectId));
            }
            finally { session.DestroyObject(data); }
        });
    }

    // CKA_START_DATE and CKA_END_DATE, CK_DATE structures, round-trip to the day.
    internal static void Assert_KeyDates_RoundTrip(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        WithSession(backend, session =>
        {
            var start = new DateTime(2026, 1, 2, 0, 0, 0, DateTimeKind.Utc);
            var end = new DateTime(2031, 12, 30, 0, 0, 0, DateTimeKind.Utc);
            using var attrStart = new ObjectAttribute(CKA.CKA_START_DATE, start);
            using var attrEnd = new ObjectAttribute(CKA.CKA_END_DATE, end);
            ObjectHandle key = GenerateAesKey(session, attrStart, attrEnd);
            try
            {
                using var dates = session.GetAttributeValue(key, [CKA.CKA_START_DATE, CKA.CKA_END_DATE]);
                Assert.Equal(start, dates[0].GetValueAsDateTime());
                Assert.Equal(end, dates[1].GetValueAsDateTime());
            }
            finally { session.DestroyObject(key); }
        });
    }

    // === Malformed templates ===================================================

    public static TheoryData<string> MalformedTemplates => ["no CKA_CLASS", "an undefined class", "an AES key with no value", "an AES key of 13 bytes"];

    // C_CreateObject refuses a template it cannot make an object from (§5.7): TEMPLATE_INCOMPLETE for a
    // missing attribute; for an impossible value ATTRIBUTE_VALUE_INVALID, or the more specific
    // TEMPLATE_INCONSISTENT or KEY_SIZE_RANGE; and creates nothing. acceptedByTheBackend records a backend
    // that creates the object anyway.
    internal static void Assert_MalformedTemplate_CreatesNothing(IPkcs11Backend backend, string malformed, CKR[]? alsoAccepted = null, bool acceptedByTheBackend = false, bool leavesAnObjectBehind = false)
    {
        WithSession(backend, session =>
        {
            string label = $"kl-malformed-{Guid.NewGuid():N}";
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var attrData = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
            using var attrUndefined = new ObjectAttribute(CKA.CKA_CLASS, (ulong)0x7FFF_FF00UL);
            using var attrSecret = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var attrAes = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
            using var attrShort = new ObjectAttribute(CKA.CKA_VALUE, new byte[13]);
            List<ObjectAttribute> template = malformed switch
            {
                "no CKA_CLASS" => [attrToken, attrLabel],
                "an undefined class" => [attrUndefined, attrToken, attrLabel],
                "an AES key with no value" => [attrSecret, attrAes, attrToken, attrLabel],
                _ => [attrSecret, attrAes, attrToken, attrLabel, attrShort],
            };
            CKR[] accepted = malformed switch
            {
                "no CKA_CLASS" => [CKR.CKR_TEMPLATE_INCOMPLETE, .. alsoAccepted ?? []],
                "an AES key with no value" => [CKR.CKR_TEMPLATE_INCOMPLETE, CKR.CKR_KEY_SIZE_RANGE, .. alsoAccepted ?? []],
                "an undefined class" => [CKR.CKR_ATTRIBUTE_VALUE_INVALID, CKR.CKR_TEMPLATE_INCONSISTENT, .. alsoAccepted ?? []],
                _ => [CKR.CKR_ATTRIBUTE_VALUE_INVALID, CKR.CKR_KEY_SIZE_RANGE, CKR.CKR_TEMPLATE_INCONSISTENT, .. alsoAccepted ?? []],
            };
            if (acceptedByTheBackend)
            {
                ObjectHandle created = session.CreateObject(template);
                session.DestroyObject(created);
                return;
            }

            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => session.CreateObject(template));
            Assert.True(accepted.Contains(ex.ReturnValue), $"{malformed}: C_CreateObject returned {ex.ReturnValue}, expected one of {string.Join(", ", accepted)}.");
            List<ObjectHandle> left = session.FindAllObjects([attrLabel]);
            if (leavesAnObjectBehind)
            {
                // Recorded, and removed: a backend that refuses the template but keeps the object it started.
                Assert.NotEmpty(left);
                foreach (ObjectHandle handle in left)
                    session.DestroyObject(handle);
                return;
            }
            Assert.Empty(left);
        });
    }

    public static TheoryData<string> IncompleteTemplates =>
    [
        "RSA key pair without CKA_MODULUS_BITS", "EC key pair without CKA_EC_PARAMS", "RSA public key without CKA_MODULUS",
        "RSA private key without CKA_MODULUS", "EC public key without CKA_EC_PARAMS", "EC private key without CKA_EC_PARAMS",
        "secret key without CKA_KEY_TYPE",
    ];

    // A template that leaves out an attribute the object needs is refused with CKR_TEMPLATE_INCOMPLETE and
    // creates nothing (§4.1.1, point 4). Each left-out attribute is one its table says MUST be specified:
    // CKA_MODULUS_BITS and the public key's CKA_EC_PARAMS when a key pair is generated (footnote 3, §6.1.2,
    // §6.3.3), CKA_MODULUS, CKA_EC_PARAMS and CKA_KEY_TYPE when a key is created (footnote 1, §6.1.2, §6.1.3,
    // §6.3.3, §6.3.4, §4.8). Every other value in the template is valid. Nothing carries the case's label after.
    // leavesAnObjectBehind records a backend that refuses the template but keeps the object it started.
    internal static void Assert_IncompleteTemplate_IsTemplateIncomplete(IPkcs11Backend backend, string incomplete, bool leavesAnObjectBehind = false)
    {
        if (incomplete.StartsWith("RSA key pair", StringComparison.Ordinal))
            backend.RequireMechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        else if (incomplete.StartsWith("EC key pair", StringComparison.Ordinal))
            backend.RequireMechanism(CKM.CKM_EC_KEY_PAIR_GEN);
        WithSession(backend, session =>
        {
            string label = $"kl-incomplete-{Guid.NewGuid():N}";
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var attrPublic = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
            using var attrPrivate = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            using var attrSecret = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var attrRsa = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
            using var attrEc = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
            using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
            using var attrVerify = new ObjectAttribute(CKA.CKA_VERIFY, true);
            using var attrSign = new ObjectAttribute(CKA.CKA_SIGN, true);
            using var attrEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
            using var attrModulusBits = new ObjectAttribute(CKA.CKA_MODULUS_BITS, 2048UL);
            using var attrPublicExponent = new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, (byte[])[0x01, 0x00, 0x01]);
            using var attrPrivateExponent = new ObjectAttribute(CKA.CKA_PRIVATE_EXPONENT, RandomNumberGenerator.GetBytes(256));
            using var attrEcParams = new ObjectAttribute(CKA.CKA_EC_PARAMS, TestKeys.EcP256Oid);
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            ECParameters ec = ecdsa.ExportParameters(includePrivateParameters: true);
            using var attrEcPoint = new ObjectAttribute(CKA.CKA_EC_POINT, TestKeys.DerEcPoint(ec.Q.X!, ec.Q.Y!));
            using var attrEcValue = new ObjectAttribute(CKA.CKA_VALUE, ec.D!);
            using var attrValue32 = new ObjectAttribute(CKA.CKA_VALUE, RandomNumberGenerator.GetBytes(32));

            Action refused = incomplete switch
            {
                "RSA key pair without CKA_MODULUS_BITS" => () => session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
                    [attrToken, attrLabel, attrVerify, attrPublicExponent], [attrToken, attrLabel, attrSign, attrSensitive], out _, out _),
                "EC key pair without CKA_EC_PARAMS" => () => session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN),
                    [attrToken, attrLabel, attrVerify], [attrToken, attrLabel, attrSign, attrSensitive], out _, out _),
                "RSA public key without CKA_MODULUS" => () => session.CreateObject([attrPublic, attrRsa, attrToken, attrLabel, attrVerify, attrPublicExponent]),
                "RSA private key without CKA_MODULUS" => () => session.CreateObject([attrPrivate, attrRsa, attrToken, attrLabel, attrSign, attrSensitive, attrPublicExponent, attrPrivateExponent]),
                "EC public key without CKA_EC_PARAMS" => () => session.CreateObject([attrPublic, attrEc, attrToken, attrLabel, attrVerify, attrEcPoint]),
                "EC private key without CKA_EC_PARAMS" => () => session.CreateObject([attrPrivate, attrEc, attrToken, attrLabel, attrSign, attrSensitive, attrEcValue]),
                _ => () => session.CreateObject([attrSecret, attrToken, attrLabel, attrEncrypt, attrSensitive, attrValue32]),
            };
            Exception? ex = Record.Exception(refused);
            List<ObjectHandle> left = session.FindAllObjects([attrLabel]);
            foreach (ObjectHandle handle in left)
                session.DestroyObject(handle);
            Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_TEMPLATE_INCOMPLETE },
                $"{incomplete}: expected CKR_TEMPLATE_INCOMPLETE, got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "success"}.");
            if (leavesAnObjectBehind)
                Assert.NotEmpty(left);
            else
                Assert.True(left.Count == 0, $"{incomplete}: the refused call left {left.Count} object(s) behind.");
        });
    }

    public static TheoryData<string> InconsistentTemplates =>
    [
        "AES key generated as CKK_GENERIC_SECRET", "AES key generated as CKO_DATA", "EC key pair with an RSA private key",
        "EC key pair with a private-key class for the public key", "secret key of type CKK_EC", "private key of type CKK_AES",
        "data object from an HKDF derive",
    ];

    // A template whose class or key type contradicts the mechanism, or the object's other attributes, is
    // refused with CKR_TEMPLATE_INCONSISTENT and creates nothing. C_GenerateKey and C_GenerateKeyPair say so for
    // a key type or class the mechanism does not make (§5.18.1, §5.18.2); C_CreateObject of a secret key of an
    // asymmetric key type, or a private key of a symmetric one, is the set of valid values that cannot be
    // satisfied together of §4.1.1 point 5; and CKM_HKDF_DERIVE contributes CKA_CLASS itself (§6.62.3: a secret
    // key; CKM_HKDF_DATA is the one that makes a data object, §6.62.4), so a template asking for CKO_DATA
    // contradicts it. C_CreateObject and C_DeriveKey may also answer CKR_ATTRIBUTE_VALUE_INVALID: neither says
    // which code a class or key type that does not fit the object takes, and §4.1.1 point 2 (a value that is not
    // valid for the attribute) can be read to cover it. Nothing carries the case's label after.
    internal static void Assert_InconsistentTemplate_IsTemplateInconsistent(IPkcs11Backend backend, string inconsistent)
    {
        if (inconsistent.StartsWith("AES key generated", StringComparison.Ordinal))
            backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        else if (inconsistent.StartsWith("EC key pair", StringComparison.Ordinal))
            backend.RequireMechanism(CKM.CKM_EC_KEY_PAIR_GEN);
        else if (inconsistent == "data object from an HKDF derive")
            backend.RequireMechanism(CKM.CKM_HKDF_DERIVE);
        WithSession(backend, session =>
        {
            string label = $"kl-inconsistent-{Guid.NewGuid():N}";
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            using var attrInput = new ObjectAttribute(CKA.CKA_LABEL, label + "-input");
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var attrData = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
            using var attrSecret = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var attrPrivate = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            using var attrAes = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
            using var attrGeneric = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
            using var attrEc = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC);
            using var attrRsa = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
            using var attrLen32 = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
            using var attrValue32 = new ObjectAttribute(CKA.CKA_VALUE, RandomNumberGenerator.GetBytes(32));
            using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
            using var attrEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
            using var attrDecrypt = new ObjectAttribute(CKA.CKA_DECRYPT, true);
            using var attrSign = new ObjectAttribute(CKA.CKA_SIGN, true);
            using var attrVerify = new ObjectAttribute(CKA.CKA_VERIFY, true);
            using var attrDerive = new ObjectAttribute(CKA.CKA_DERIVE, true);
            using var attrEcParams = new ObjectAttribute(CKA.CKA_EC_PARAMS, TestKeys.EcP256Oid);

            var created = new List<ObjectHandle>();
            try
            {
                Action refused;
                switch (inconsistent)
                {
                    case "AES key generated as CKK_GENERIC_SECRET":
                        refused = () => created.Add(session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), [attrGeneric, attrLen32, attrToken, attrLabel, attrEncrypt, attrSensitive]));
                        break;
                    case "AES key generated as CKO_DATA":
                        refused = () => created.Add(session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), [attrData, attrLen32, attrToken, attrLabel]));
                        break;
                    case "EC key pair with an RSA private key":
                        refused = () => GenerateEcKeyPair([attrToken, attrLabel, attrVerify, attrEcParams], [attrRsa, attrToken, attrLabel, attrSign, attrSensitive]);
                        break;
                    case "EC key pair with a private-key class for the public key":
                        refused = () => GenerateEcKeyPair([attrPrivate, attrToken, attrLabel, attrVerify, attrEcParams], [attrToken, attrLabel, attrSign, attrSensitive]);
                        break;
                    case "secret key of type CKK_EC":
                        refused = () => created.Add(session.CreateObject([attrSecret, attrEc, attrToken, attrLabel, attrEncrypt, attrSensitive, attrValue32]));
                        break;
                    case "private key of type CKK_AES":
                        refused = () => created.Add(session.CreateObject([attrPrivate, attrAes, attrToken, attrLabel, attrDecrypt, attrSensitive, attrValue32]));
                        break;
                    default: // data object from an HKDF derive
                        {
                            ObjectHandle baseKey = session.CreateObject([attrSecret, attrGeneric, attrToken, attrInput, attrDerive, attrSensitive, attrValue32]);
                            created.Add(baseKey);
                            var mechanism = new Mechanism(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256, "kl"u8));
                            refused = () => created.Add(session.DeriveKey(mechanism, baseKey, [attrData, attrLen32, attrToken, attrLabel]));
                            break;
                        }
                }
                Exception? ex = Record.Exception(refused);
                List<ObjectHandle> left = session.FindAllObjects([attrLabel]);
                CKR[] accepted = inconsistent.Contains(" generated ", StringComparison.Ordinal) || inconsistent.StartsWith("EC key pair", StringComparison.Ordinal)
                    ? [CKR.CKR_TEMPLATE_INCONSISTENT]
                    : [CKR.CKR_TEMPLATE_INCONSISTENT, CKR.CKR_ATTRIBUTE_VALUE_INVALID];
                Assert.True(ex is Pkcs11Exception pex && accepted.Contains(pex.ReturnValue),
                    $"{inconsistent}: expected {string.Join(" or ", accepted)}, got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "success"}.");
                Assert.True(left.Count == 0, $"{inconsistent}: the refused call left {left.Count} object(s) behind.");
            }
            finally
            {
                foreach (ObjectHandle handle in created.Concat(session.FindAllObjects([attrLabel])).DistinctBy(h => h.ObjectId))
                    session.DestroyObject(handle);
            }

            void GenerateEcKeyPair(List<ObjectAttribute> publicTemplate, List<ObjectAttribute> privateTemplate)
            {
                session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), publicTemplate, privateTemplate, out ObjectHandle publicKey, out ObjectHandle privateKey);
                created.Add(publicKey);
                created.Add(privateKey);
            }
        });
    }

    // === Read-only attributes ==================================================

    // The token gives every object a CKA_UNIQUE_ID of its own, and nobody else can (§4.4.1): two objects and
    // a copy of one have non-empty, distinct values, and a CKA_UNIQUE_ID in the template of C_CreateObject or
    // C_CopyObject, or in C_SetAttributeValue, is refused with CKR_ATTRIBUTE_READ_ONLY, creating nothing and
    // leaving the value as it was. Skips a token that does not report CKA_UNIQUE_ID (a PKCS#11 v2.40 one).
    internal static void Assert_UniqueId_IsTheTokensAndReadOnly(IPkcs11Backend backend)
    {
        WithSession(backend, session =>
        {
            string label = $"kl-unique-id-{Guid.NewGuid():N}";
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            ObjectHandle first = CreateDataObject(session, label + "-1", [0x01]);
            ObjectHandle second = CreateDataObject(session, label + "-2", [0x02]);
            var copies = new List<ObjectHandle>();
            try
            {
                using var read = session.GetAttributeValue(first, [CKA.CKA_UNIQUE_ID]);
                if (read[0].CannotBeRead)
                    Assert.Skip("The backend does not report CKA_UNIQUE_ID.");
                ObjectHandle copy = session.CopyObject(first, []);
                copies.Add(copy);
                byte[][] ids = [Read(session, first, CKA.CKA_UNIQUE_ID), Read(session, second, CKA.CKA_UNIQUE_ID), Read(session, copy, CKA.CKA_UNIQUE_ID)];
                Assert.All(ids, id => Assert.NotEmpty(id));
                Assert.Equal(3, ids.Select(Convert.ToHexString).Distinct().Count());

                using var attrUniqueId = new ObjectAttribute(CKA.CKA_UNIQUE_ID, "kl-chosen-id");
                var created = Assert.ThrowsAny<Pkcs11Exception>(() => copies.Add(CreateDataObject(session, label, [0x03], attrUniqueId)));
                Assert.Equal(CKR.CKR_ATTRIBUTE_READ_ONLY, created.ReturnValue);
                var copied = Assert.ThrowsAny<Pkcs11Exception>(() => copies.Add(session.CopyObject(first, [attrUniqueId, attrLabel])));
                Assert.Equal(CKR.CKR_ATTRIBUTE_READ_ONLY, copied.ReturnValue);
                var set = Assert.ThrowsAny<Pkcs11Exception>(() => Set(session, first, attrUniqueId));
                Assert.Equal(CKR.CKR_ATTRIBUTE_READ_ONLY, set.ReturnValue);
                Assert.Equal(ids[0], Read(session, first, CKA.CKA_UNIQUE_ID));
                Assert.Empty(session.FindAllObjects([attrLabel]));
            }
            finally
            {
                foreach (ObjectHandle handle in copies.Concat(session.FindAllObjects([attrLabel])).DistinctBy(h => h.ObjectId))
                    session.DestroyObject(handle);
                session.DestroyObject(second);
                session.DestroyObject(first);
            }
        });
    }

    public static TheoryData<string> KeyComponents =>
        ["AES CKA_VALUE", "RSA CKA_MODULUS", "RSA CKA_PUBLIC_EXPONENT", "EC CKA_EC_POINT", "AES CKA_VALUE in a copy"];

    // A key's material is fixed once the key exists: CKA_VALUE of an AES key, CKA_MODULUS and
    // CKA_PUBLIC_EXPONENT of an RSA public key and CKA_EC_POINT of an EC public key have no footnote 8 in their
    // tables (§6.7, §6.1.2, §6.3.3), so C_SetAttributeValue of a new value is refused with
    // CKR_ATTRIBUTE_READ_ONLY (§4.1.2, §4.1.1 point 3), and so is a new CKA_VALUE in the template of
    // C_CopyObject, which may change only the modifiable attributes and four storage ones (§4.1.3). The value
    // reads back as it was and no copy is made. Each key is imported non-sensitive, so its value can be read.
    internal static void Assert_KeyComponent_IsReadOnly(IPkcs11Backend backend, string component)
    {
        WithSession(backend, session =>
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            string label = $"kl-component-{Guid.NewGuid():N}";
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var rsa = RSA.Create(2048);
            RSAParameters rsaKey = rsa.ExportParameters(includePrivateParameters: false);
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            ECParameters ecKey = ecdsa.ExportParameters(includePrivateParameters: false);
            using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            ECParameters otherKey = other.ExportParameters(includePrivateParameters: false);

            (ObjectHandle key, CKA attribute, byte[] changed) = component switch
            {
                "RSA CKA_MODULUS" => (TestKeys.ImportRsaPublicKey(session, rsaKey.Modulus!, rsaKey.Exponent!), CKA.CKA_MODULUS, RandomModulus()),
                "RSA CKA_PUBLIC_EXPONENT" => (TestKeys.ImportRsaPublicKey(session, rsaKey.Modulus!, rsaKey.Exponent!), CKA.CKA_PUBLIC_EXPONENT, [0x03]),
                "EC CKA_EC_POINT" => (TestKeys.ImportEcP256PublicKey(session, ecKey.Q.X!, ecKey.Q.Y!), CKA.CKA_EC_POINT, TestKeys.DerEcPoint(otherKey.Q.X!, otherKey.Q.Y!)),
                _ => (CreateReadableAesKey(), CKA.CKA_VALUE, RandomNumberGenerator.GetBytes(32)),
            };
            try
            {
                byte[] original = Read(session, key, attribute);
                using var attrChanged = new ObjectAttribute(attribute, changed);
                Pkcs11Exception ex;
                if (component.EndsWith(" in a copy", StringComparison.Ordinal))
                    ex = Assert.ThrowsAny<Pkcs11Exception>(() => session.DestroyObject(session.CopyObject(key, [attrChanged, attrLabel])));
                else
                    ex = Assert.ThrowsAny<Pkcs11Exception>(() => Set(session, key, attrChanged));
                Assert.True(ex.ReturnValue == CKR.CKR_ATTRIBUTE_READ_ONLY, $"{component}: the change was refused with {ex.ReturnValue}, not CKR_ATTRIBUTE_READ_ONLY.");
                Assert.Equal(original, Read(session, key, attribute));
            }
            finally
            {
                foreach (ObjectHandle handle in session.FindAllObjects([attrLabel]))
                    session.DestroyObject(handle);
                session.DestroyObject(key);
            }

            ObjectHandle CreateReadableAesKey()
            {
                using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
                using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, false);
                using var attrExtractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, true);
                using var attrEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
                using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, RandomNumberGenerator.GetBytes(32));
                return session.CreateObject([attrClass, attrKeyType, attrToken, attrSensitive, attrExtractable, attrEncrypt, attrValue]);
            }

            byte[] RandomModulus()
            {
                using var another = RSA.Create(2048);
                return another.ExportParameters(includePrivateParameters: false).Modulus!;
            }
        });
    }

    public static TheoryData<string> ProvenanceInATemplate =>
    [
        "C_CreateObject with CKA_ALWAYS_SENSITIVE", "C_CreateObject with CKA_NEVER_EXTRACTABLE",
        "C_GenerateKey with CKA_ALWAYS_SENSITIVE", "C_GenerateKey with CKA_NEVER_EXTRACTABLE",
    ];

    // CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE are the token's account of a key's history: footnotes 2
    // and 4 of Table 30 say they MUST NOT be specified when the key is created or generated, and a template that
    // gives a read-only attribute is refused with CKR_ATTRIBUTE_READ_ONLY (§4.1.1 point 3). Each template states
    // the opposite of what the token would record (TRUE for an imported key, FALSE for a key generated sensitive
    // and unextractable), so it cannot pass as a repeat of the module's own value (§4.1.1 point 6). Nothing is
    // created. leavesAnObjectBehind records a backend that refuses the template but keeps the object it started.
    internal static void Assert_ProvenanceAttributeInATemplate_IsReadOnly(IPkcs11Backend backend, string row, bool leavesAnObjectBehind = false)
    {
        bool generate = row.StartsWith("C_GenerateKey", StringComparison.Ordinal);
        if (generate)
            backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        CKA attribute = row.EndsWith("CKA_ALWAYS_SENSITIVE", StringComparison.Ordinal) ? CKA.CKA_ALWAYS_SENSITIVE : CKA.CKA_NEVER_EXTRACTABLE;
        WithSession(backend, session =>
        {
            string label = $"kl-provenance-{Guid.NewGuid():N}";
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            using var attrProvenance = new ObjectAttribute(attribute, !generate);
            var ex = Assert.ThrowsAny<Pkcs11Exception>(() =>
            {
                ObjectHandle made = generate
                    ? GenerateAesKey(session, attrLabel, attrProvenance)
                    : CreateSensitiveAesKey(session, attrLabel, attrProvenance);
                session.DestroyObject(made);
            });
            List<ObjectHandle> left = session.FindAllObjects([attrLabel]);
            foreach (ObjectHandle handle in left)
                session.DestroyObject(handle);
            Assert.True(ex.ReturnValue == CKR.CKR_ATTRIBUTE_READ_ONLY, $"{row}: refused with {ex.ReturnValue}, not CKR_ATTRIBUTE_READ_ONLY.");
            if (leavesAnObjectBehind)
                Assert.NotEmpty(left);
            else
                Assert.Empty(left);
        });
    }

    private static ObjectHandle CreateSensitiveAesKey(Pkcs11SessionCore session, params ObjectAttribute[] extra)
    {
        using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var attrKeyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
        using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
        using var attrExtractable = new ObjectAttribute(CKA.CKA_EXTRACTABLE, false);
        using var attrEncrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, RandomNumberGenerator.GetBytes(32));
        return session.CreateObject([attrClass, attrKeyType, attrToken, attrSensitive, attrExtractable, attrEncrypt, attrValue, .. extra]);
    }

    // === Malformed attribute values ============================================

    public static TheoryData<string> MalformedAttributes =>
    [
        "C_CreateObject with a 4-byte CKA_TOKEN", "C_CreateObject with CKA_TOKEN NULL and ulValueLen 1",
        "C_CreateObject with CKA_VALUE NULL and ulValueLen 16", "C_FindObjectsInit with CKA_LABEL NULL and ulValueLen 4",
        "C_FindObjectsInit with a 4-byte CKA_TOKEN",
    ];

    // An attribute whose value does not fit its type, or that names a length but no value, is refused without
    // harm to the module. Through the raw call, since the library never builds such a template. C_CreateObject
    // of a data object with a CK_BBOOL of 4 bytes answers CKR_ATTRIBUTE_VALUE_INVALID (§4.1.1 point 2), and
    // with a NULL pValue and a non-zero ulValueLen CKR_ATTRIBUTE_VALUE_INVALID or CKR_ARGUMENTS_BAD; nothing is
    // created. C_FindObjectsInit with either refuses it with one of those codes, or starts a search that
    // matches nothing: no object has such a value (§5.7.7). The session works afterwards. A module that crashes
    // here takes the test host with it, so its wrapper skips the row.
    // leavesAnObjectBehind records a backend that refuses the template but keeps the object it started.
    internal static void Assert_MalformedAttribute_IsRefusedHarmlessly(IPkcs11Backend backend, string malformed, bool leavesAnObjectBehind = false)
    {
        WithSession(backend, session =>
        {
            LowLevelPkcs11Library lowLevel = backend.Library.LowLevelLibrary!;
            var sid = (NativeCULong)session.SessionId;
            string label = $"kl-malformed-attribute-{Guid.NewGuid():N}";
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            // A search for the case's label finds what a refused C_CreateObject left, so the label goes in too.
            ObjectHandle data = CreateDataObject(session, label + "-existing", [0x01]);
            var allocations = new List<IntPtr>();
            try
            {
                CK_ATTRIBUTE Value(CKA type, byte[] value)
                {
                    IntPtr p = Marshal.AllocHGlobal(Math.Max(value.Length, 1));
                    allocations.Add(p);
                    Marshal.Copy(value, 0, p, value.Length);
                    return new CK_ATTRIBUTE { type = (NativeCULong)(ulong)type, value = p, valueLen = (NativeCULong)(ulong)value.Length };
                }
                CK_ATTRIBUTE Null(CKA type, ulong length) => new() { type = (NativeCULong)(ulong)type, value = IntPtr.Zero, valueLen = (NativeCULong)length };
                byte[] classBytes = new byte[Unsafe.SizeOf<NativeCULong>()];
                MemoryMarshal.Write(classBytes, (NativeCULong)(ulong)CKO.CKO_DATA);

                CK_ATTRIBUTE[] dataObject = [Value(CKA.CKA_CLASS, classBytes), Value(CKA.CKA_LABEL, System.Text.Encoding.UTF8.GetBytes(label))];
                CK_ATTRIBUTE[] template = malformed switch
                {
                    "C_CreateObject with a 4-byte CKA_TOKEN" => [.. dataObject, Value(CKA.CKA_TOKEN, [0x00, 0x00, 0x00, 0x00])],
                    "C_CreateObject with CKA_TOKEN NULL and ulValueLen 1" => [.. dataObject, Null(CKA.CKA_TOKEN, 1)],
                    "C_CreateObject with CKA_VALUE NULL and ulValueLen 16" => [.. dataObject, Value(CKA.CKA_TOKEN, [0x00]), Null(CKA.CKA_VALUE, 16)],
                    "C_FindObjectsInit with CKA_LABEL NULL and ulValueLen 4" => [Value(CKA.CKA_CLASS, classBytes), Null(CKA.CKA_LABEL, 4)],
                    _ => [Value(CKA.CKA_CLASS, classBytes), Value(CKA.CKA_TOKEN, [0x00, 0x00, 0x00, 0x00])],
                };

                if (malformed.StartsWith("C_CreateObject", StringComparison.Ordinal))
                {
                    CKR rv = lowLevel.C_CreateObject(sid, template, out NativeCULong created);
                    if (rv == CKR.CKR_OK)
                        lowLevel.C_DestroyObject(sid, created);
                    CKR[] accepted = malformed.Contains("NULL", StringComparison.Ordinal)
                        ? [CKR.CKR_ATTRIBUTE_VALUE_INVALID, CKR.CKR_ARGUMENTS_BAD]
                        : [CKR.CKR_ATTRIBUTE_VALUE_INVALID];
                    Assert.True(accepted.Contains(rv), $"{malformed}: returned {rv}, expected {string.Join(" or ", accepted)}.");
                    List<ObjectHandle> left = session.FindAllObjects([attrLabel]);
                    foreach (ObjectHandle handle in left)
                        session.DestroyObject(handle);
                    if (leavesAnObjectBehind)
                        Assert.NotEmpty(left);
                    else
                        Assert.Empty(left);
                }
                else
                {
                    CKR rv = lowLevel.C_FindObjectsInit(sid, template);
                    if (rv == CKR.CKR_OK)
                    {
                        var found = new NativeCULong[16];
                        CKR findRv = lowLevel.C_FindObjects(sid, found, out NativeCULong count);
                        CKR finalRv = lowLevel.C_FindObjectsFinal(sid);
                        Assert.Equal(CKR.CKR_OK, findRv);
                        Assert.Equal(CKR.CKR_OK, finalRv);
                        Assert.True((ulong)count == 0, $"{malformed}: the search matched {(ulong)count} object(s).");
                    }
                    else
                    {
                        Assert.True(rv is CKR.CKR_ATTRIBUTE_VALUE_INVALID or CKR.CKR_ARGUMENTS_BAD, $"{malformed}: returned {rv}.");
                    }
                }

                // The module still answers, and the session still searches.
                Assert.Equal(CKR.CKR_OK, lowLevel.C_GetSessionInfo(sid, out _));
                using var attrExisting = new ObjectAttribute(CKA.CKA_LABEL, label + "-existing");
                Assert.Equal([data.ObjectId], session.FindAllObjects([attrExisting]).Select(h => h.ObjectId));
            }
            finally
            {
                foreach (IntPtr p in allocations)
                    Marshal.FreeHGlobal(p);
                session.DestroyObject(data);
            }
        });
    }

    // === What a copy keeps =====================================================

    // A copy is the original with the template's changes (§5.7.2): with a template that names only CKA_LABEL,
    // the copy of a token object is a token object and the copy of a session object a session object. The
    // token objects are destroyed whatever happens.
    internal static void Assert_CopyObject_KeepsCkaToken(IPkcs11Backend backend)
    {
        if (!backend.SupportsTokenObjects)
            Assert.Skip("The backend has no token objects.");
        WithSession(backend, session =>
        {
            string label = $"kl-copy-token-{Guid.NewGuid():N}";
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            using var attrCopyLabel = new ObjectAttribute(CKA.CKA_LABEL, label + "-copy");
            using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
            using var attrOnToken = new ObjectAttribute(CKA.CKA_TOKEN, true);
            using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, (byte[])[0x01]);
            var made = new List<ObjectHandle>();
            try
            {
                ObjectHandle tokenObject = session.CreateObject([attrClass, attrOnToken, attrLabel, attrValue]);
                made.Add(tokenObject);
                ObjectHandle tokenCopy = session.CopyObject(tokenObject, [attrCopyLabel]);
                made.Add(tokenCopy);
                Assert.True(ReadBool(session, tokenCopy, CKA.CKA_TOKEN), "The copy of a token object is a session object.");

                ObjectHandle sessionObject = CreateDataObject(session, label, [0x02]);
                made.Add(sessionObject);
                ObjectHandle sessionCopy = session.CopyObject(sessionObject, [attrCopyLabel]);
                made.Add(sessionCopy);
                Assert.False(ReadBool(session, sessionCopy, CKA.CKA_TOKEN), "The copy of a session object is a token object.");
            }
            finally
            {
                using var attrCopies = new ObjectAttribute(CKA.CKA_LABEL, label + "-copy");
                foreach (ObjectHandle handle in made.Concat(session.FindAllObjects([attrLabel])).Concat(session.FindAllObjects([attrCopies])).DistinctBy(h => h.ObjectId))
                    session.DestroyObject(handle);
            }
        });
    }

    // A copy of a data object keeps its CKA_VALUE, CKA_APPLICATION and CKA_OBJECT_ID (Table 20): the template
    // changes only CKA_LABEL, and the original keeps its own label.
    internal static void Assert_CopyObject_KeepsADataObjectsFields(IPkcs11Backend backend)
    {
        WithSession(backend, session =>
        {
            byte[] value = RandomNumberGenerator.GetBytes(48);
            byte[] objectId = [0x06, 0x03, 0x2A, 0x03, 0x04]; // OID 1.2.3.4
            using var attrApplication = new ObjectAttribute(CKA.CKA_APPLICATION, "kl-application");
            using var attrObjectId = new ObjectAttribute(CKA.CKA_OBJECT_ID, objectId);
            ObjectHandle original = CreateDataObject(session, "kl-copy-original", value, attrApplication, attrObjectId);
            ObjectHandle? copy = null;
            try
            {
                using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, "kl-copy-of-data");
                copy = session.CopyObject(original, [attrLabel]);
                foreach ((string which, ObjectHandle handle) in new[] { ("original", original), ("copy", copy.Value) })
                {
                    using var read = session.GetAttributeValue(handle, [CKA.CKA_VALUE, CKA.CKA_APPLICATION, CKA.CKA_OBJECT_ID]);
                    Assert.True(read.All(a => !a.CannotBeRead), $"The {which} does not report every data object attribute it was given.");
                    Assert.Equal(value, read[0].GetValueAsByteArray());
                    Assert.Equal("kl-application", read[1].GetValueAsString());
                    Assert.Equal(objectId, read[2].GetValueAsByteArray());
                }
                using var copyLabel = session.GetAttributeValue(copy.Value, [CKA.CKA_LABEL]);
                Assert.Equal("kl-copy-of-data", copyLabel[0].GetValueAsString());
                using var originalLabel = session.GetAttributeValue(original, [CKA.CKA_LABEL]);
                Assert.Equal("kl-copy-original", originalLabel[0].GetValueAsString());
            }
            finally
            {
                if (copy is { } made)
                    session.DestroyObject(made);
                session.DestroyObject(original);
            }
        });
    }

    // CKA_COPYABLE "Can't be set to TRUE once it is set to FALSE" (Table 19): on an object created with
    // CKA_COPYABLE = FALSE, C_SetAttributeValue(CKA_COPYABLE = TRUE) is refused with CKR_ATTRIBUTE_READ_ONLY
    // (§4.1.1 point 3) or leaves it FALSE, and C_CopyObject is still refused with CKR_ACTION_PROHIBITED (§4.1.3).
    // The copy's template names a label: SoftHSM2 refuses a NULL template with CKR_ARGUMENTS_BAD before it looks
    // at CKA_COPYABLE.
    internal static void Assert_UncopyableObject_StaysUncopyable(IPkcs11Backend backend)
    {
        WithSession(backend, session =>
        {
            using var copyable = new ObjectAttribute(CKA.CKA_COPYABLE, false);
            ObjectHandle data = CreateDataObject(session, "kl-stays-uncopyable", [0x01], copyable);
            try
            {
                Assert.False(ReadBool(session, data, CKA.CKA_COPYABLE));
                using var undone = new ObjectAttribute(CKA.CKA_COPYABLE, true);
                Exception? set = Record.Exception(() => Set(session, data, undone));
                Assert.True(set is null or Pkcs11Exception { ReturnValue: CKR.CKR_ATTRIBUTE_READ_ONLY },
                    $"C_SetAttributeValue(CKA_COPYABLE = TRUE) answered {(set as Pkcs11Exception)?.ReturnValue.ToString() ?? set?.GetType().Name}.");
                Assert.False(ReadBool(session, data, CKA.CKA_COPYABLE), "CKA_COPYABLE went back from FALSE to TRUE.");
                using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, "kl-stays-uncopyable-copy");
                var ex = Assert.ThrowsAny<Pkcs11Exception>(() => session.DestroyObject(session.CopyObject(data, [attrLabel])));
                Assert.Equal(CKR.CKR_ACTION_PROHIBITED, ex.ReturnValue);
            }
            finally { session.DestroyObject(data); }
        });
    }

    // CKA_MODIFIABLE, CKA_COPYABLE and CKA_DESTROYABLE default to TRUE (Table 19): an object created without them
    // reads all three TRUE, and can be copied, changed and destroyed.
    internal static void Assert_StorageControls_DefaultToTrue(IPkcs11Backend backend)
    {
        WithSession(backend, session =>
        {
            ObjectHandle data = CreateDataObject(session, "kl-defaults", [0x01]);
            bool destroyed = false;
            try
            {
                using (var read = session.GetAttributeValue(data, [CKA.CKA_MODIFIABLE, CKA.CKA_COPYABLE, CKA.CKA_DESTROYABLE]))
                {
                    Assert.True(read[0].GetValueAsBool(), "CKA_MODIFIABLE defaulted to FALSE.");
                    Assert.True(read[1].GetValueAsBool(), "CKA_COPYABLE defaulted to FALSE.");
                    Assert.True(read[2].GetValueAsBool(), "CKA_DESTROYABLE defaulted to FALSE.");
                }
                using var copyLabel = new ObjectAttribute(CKA.CKA_LABEL, "kl-defaults-copy");
                session.DestroyObject(session.CopyObject(data, [copyLabel]));
                using var label = new ObjectAttribute(CKA.CKA_LABEL, "kl-defaults-changed");
                Set(session, data, label);
                session.DestroyObject(data);
                destroyed = true;
            }
            finally
            {
                if (!destroyed)
                    session.DestroyObject(data);
            }
        });
    }
}
