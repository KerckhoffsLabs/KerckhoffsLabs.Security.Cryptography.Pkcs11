using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;
using Xunit.Sdk;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Compat;

/// <summary>
/// One test per NSS softoken bug a gate on <see cref="NssBackendFixture"/> works around: each reproduces
/// the bug directly and asserts that it is still there. When an NSS bump brings the upstream fix, the
/// matching test fails, telling us to remove the gate so the shared test cases run again.
/// </summary>
[Collection("Nss")]
public sealed class NssQuirkTests(NssBackendFixture backend)
{
    private readonly IPkcs11Backend _backend = backend;

    // https://bugzilla.mozilla.org/show_bug.cgi?id=2075845
    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void CmacVerify_QuirkStillPresent()
    {
        _backend.RequireMechanism(CKM.CKM_AES_CMAC);
        using var session = _backend.OpenSession();
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label($"quirk-cmac-{Guid.NewGuid():N}").Value(new byte[16]).Sign().Verify().Build();
        using var key = session.ImportKey(template);
        var cmac = new Mechanism(CKM.CKM_AES_CMAC);
        byte[] mac = key.Sign(cmac, [1, 2, 3]);

        var ex = Record.Exception(() => key.Verify(cmac, [1, 2, 3], mac));

        Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_MECHANISM_INVALID },
            "C_VerifyInit with CKM_AES_CMAC no longer gives CKR_MECHANISM_INVALID " +
            $"(got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "no exception"}): set " +
            "NssBackendFixture.SupportsCmacVerify to true and delete this test.");
    }

    // https://bugzilla.mozilla.org/show_bug.cgi?id=2075840
    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void GeneratedKeyLocal_QuirkStillPresent()
    {
        _backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);
        using var session = _backend.OpenSession();
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label($"quirk-local-{Guid.NewGuid():N}").ValueLen(32).Encrypt().Build();
        using var key = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template);
        using var attributes = key.GetAttributeValue(CKA.CKA_LOCAL);

        Assert.False(attributes[0].GetValueAsBool(),
            "A key NSS generates now reports CKA_LOCAL true: set NssBackendFixture.SupportsLocalOnGeneratedKeys " +
            "to true and delete this test.");
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void SecondKeyExtractable_QuirkStillPresent()
    {
        Exception? failure = Record.Exception(() => BaseKeyProtectionTestCases.Assert_KeyMadeFromAProtectedKey_KeepsItsProtection(_backend, "CONCATENATE_BASE_AND_KEY, protected second key; unextractable only"));
        Assert.True(failure is XunitException and not SkipException,
            "NSS now takes the second key's CKA_EXTRACTABLE in CKM_CONCATENATE_BASE_AND_KEY: make " +
            "NssBackendFixture.TakesTheSecondKeysExtractability true and delete this test.");
    }

    // The mechanism-coverage quirks below drive mechanisms outside the default policy on purpose, under a scoped
    // AllowInsecure lease; the compile-time policy analyzer flags them, so it is off for these tests only.
#pragma warning disable KLPKCS11008, KLPKCS11009
    private void WithInsecureSession(Action<Internal.Pkcs11SessionCore> body)
    {
        using var session = TestKeys.OpenLoggedInSession(_backend);
        try
        {
            using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
            body(session);
        }
        finally { TestKeys.LogoutIfRequired(_backend, session); }
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Md2HmacBlockLength_QuirkStillPresent()
    {
        _backend.RequireMechanisms(CKM.CKM_MD2_HMAC, CKM.CKM_MD2);
        bool paddedTo64 = false;
        WithInsecureSession(session =>
        {
            byte[] key = [.. Enumerable.Range(0, 16).Select(i => (byte)(0x0B + i))];
            byte[] message = "probe"u8.ToArray();
            using var keyClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var keyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
            using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var sign = new ObjectAttribute(CKA.CKA_SIGN, true);
            using var value = new ObjectAttribute(CKA.CKA_VALUE, key);
            Internal.ObjectHandle handle = session.CreateObject([keyClass, keyType, token, sign, value]);
            try
            {
                byte[] mac = session.Sign(new Mechanism(CKM.CKM_MD2_HMAC), handle, message);
                byte[] Md2(byte[] data) => session.Digest(new Mechanism(CKM.CKM_MD2), data);
                byte[] padded = new byte[64];
                key.CopyTo(padded, 0);
                byte[] inner = Md2([.. padded.Select(b => (byte)(b ^ 0x36)), .. message]);
                paddedTo64 = Md2([.. padded.Select(b => (byte)(b ^ 0x5C)), .. inner]).AsSpan().SequenceEqual(mac);
            }
            finally { session.DestroyObject(handle); }
        });

        Assert.True(paddedTo64,
            "CKM_MD2_HMAC no longer pads the key to a 64-byte block: make " +
            "NssBackendFixture.NssRunsMd2HmacOverItsBlockSize true and delete this test.");
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void CamelliaValueLen_QuirkStillPresent()
    {
        _backend.RequireMechanism(CKM.CKM_CAMELLIA_KEY_GEN);
        Exception? ex = null;
        WithInsecureSession(session =>
        {
            using var keyClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var length = new ObjectAttribute(CKA.CKA_VALUE_LEN, 16UL);
            using var encrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
            Internal.ObjectHandle key = session.GenerateKey(new Mechanism(CKM.CKM_CAMELLIA_KEY_GEN), [keyClass, token, length, encrypt]);
            try
            {
                ex = Record.Exception(() =>
                {
                    using var read = session.GetAttributeValue(key, [CKA.CKA_VALUE_LEN]);
                    _ = read[0].GetValueAsUlong();
                });
            }
            finally { session.DestroyObject(key); }
        });

        Assert.True(ex is Pkcs11AttributeException,
            "CKA_VALUE_LEN of a generated Camellia key can now be read " +
            $"(got {ex?.GetType().Name ?? "a value"}): make NssBackendFixture.NssReadsAGeneratedCamelliaKeysLength true and delete this test.");
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ExtractKeyFromKeyWrap_QuirkStillPresent()
    {
        _backend.RequireMechanism(CKM.CKM_EXTRACT_KEY_FROM_KEY);
        Exception? ex = null;
        WithInsecureSession(session =>
        {
            using var keyClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var keyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET);
            using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var derive = new ObjectAttribute(CKA.CKA_DERIVE, true);
            using var value = new ObjectAttribute(CKA.CKA_VALUE, [0x32, 0x9F, 0x84, 0xA9]);
            Internal.ObjectHandle baseKey = session.CreateObject([keyClass, keyType, token, derive, value]);
            try
            {
                byte[] bit21 = new byte[Native.UnmanagedMemory.NativeULongSize];
                bit21[0] = 21; // little-endian CK_ULONG
                using var length = new ObjectAttribute(CKA.CKA_VALUE_LEN, 2UL);
                ex = Record.Exception(() =>
                    session.DestroyObject(session.DeriveKey(new Mechanism(CKM.CKM_EXTRACT_KEY_FROM_KEY, bit21), baseKey, [keyClass, keyType, token, length])));
            }
            finally { session.DestroyObject(baseKey); }
        });

        Assert.True(ex is Pkcs11Exception { ReturnValue: CKR.CKR_MECHANISM_PARAM_INVALID },
            "CKM_EXTRACT_KEY_FROM_KEY from bit 21 of a 4-byte key no longer gives CKR_MECHANISM_PARAM_INVALID " +
            $"(got {(ex as Pkcs11Exception)?.ReturnValue.ToString() ?? ex?.GetType().Name ?? "no exception"}): make " +
            "NssBackendFixture.NssExtractsAroundTheEndOfTheKey true and delete this test.");
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void GeneratedKeyMechanism_QuirkStillPresent()
    {
        Exception? ex = null;
        WithInsecureSession(session =>
        {
            using var keyClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var length = new ObjectAttribute(CKA.CKA_VALUE_LEN, 32UL);
            using var encrypt = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
            Internal.ObjectHandle key = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), [keyClass, token, length, encrypt]);
            try
            {
                ex = Record.Exception(() =>
                {
                    using var read = session.GetAttributeValue(key, [CKA.CKA_KEY_GEN_MECHANISM]);
                    _ = read[0].GetValueAsUlong();
                });
            }
            finally { session.DestroyObject(key); }
        });

        Assert.True(ex is Pkcs11AttributeException,
            $"A generated AES key now has a CKA_KEY_GEN_MECHANISM (got {ex?.GetType().Name ?? "a value"}): make " +
            "NssBackendFixture.NssRecordsAGeneratedKeysMechanism true and delete this test.");
    }
#pragma warning restore KLPKCS11008, KLPKCS11009
}
