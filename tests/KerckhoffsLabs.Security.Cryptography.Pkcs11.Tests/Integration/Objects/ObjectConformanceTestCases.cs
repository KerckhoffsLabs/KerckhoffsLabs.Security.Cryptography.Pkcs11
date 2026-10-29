using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
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
        [CKA.CKA_CLASS, CKA.CKA_KEY_TYPE, CKA.CKA_LOCAL, CKA.CKA_ALWAYS_SENSITIVE, CKA.CKA_NEVER_EXTRACTABLE, CKA.CKA_KEY_GEN_MECHANISM, CKA.CKA_VALUE_LEN];

    // An attribute a module derives, or that fixes what the object is, cannot be set after creation
    // (§4.1, Table 7 footnote 4): the call is refused with CKR_ATTRIBUTE_READ_ONLY and the attribute reads as
    // it did. ignored records a backend that returns CKR_OK and leaves the attribute as it was.
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

}
