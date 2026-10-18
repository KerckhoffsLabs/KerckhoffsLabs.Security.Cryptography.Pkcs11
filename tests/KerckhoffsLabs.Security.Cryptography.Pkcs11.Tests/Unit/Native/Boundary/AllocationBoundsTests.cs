using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Boundary;

/// <summary>
/// The memory the library allocates and lends a module, through the session's real marshalling: every
/// attribute value of every template (nested templates included), every mechanism parameter block, and
/// every buffer such a block points to lies in a live <c>UnmanagedMemory</c> block, its whole stated length
/// inside it. <see cref="AllocationBoundsModule"/> checks each one as the module would read it.
/// </summary>
/// <remarks>
/// Values of 1, 13 and 4099 bytes give a short block, an odd one and one past a page. Each case also
/// asserts which pointers were checked, so a template or parameter that stopped reaching the module would
/// not pass vacuously.
/// </remarks>
[Collection(FakeModuleCollection.Name)]
public sealed class AllocationBoundsTests
{
    private static readonly ObjectHandle Key = new(7);

    private static byte[] Bytes(int length) => [.. Enumerable.Range(1, length).Select(i => unchecked((byte)i))];

    /// <summary>
    /// One attribute of each shape the library marshals: scalars, strings, dates, byte values of three
    /// sizes, a mechanism list, an empty value, and a nested template.
    /// </summary>
    /// <returns>The template, and how many of its values (nested ones included) are non-empty.</returns>
    private static (List<ObjectAttribute> Template, int Values) EveryShape() =>
    ([
        new(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
        new(CKA.CKA_TOKEN, false),
        new(CKA.CKA_LABEL, "allocation-bounds"),
        new(CKA.CKA_START_DATE, new DateTime(2026, 10, 18)),
        new(CKA.CKA_ID, Bytes(1)),
        new(CKA.CKA_VALUE, Bytes(13)),
        new(CKA.CKA_SUBJECT, Bytes(4099)),
        new(CKA.CKA_ALLOWED_MECHANISMS, [CKM.CKM_AES_GCM, CKM.CKM_AES_CBC_PAD]),
        new(CKA.CKA_APPLICATION),
        new(CKA.CKA_WRAP_TEMPLATE, [new ObjectAttribute(CKA.CKA_ENCRYPT, true), new ObjectAttribute(CKA.CKA_ID, Bytes(13))]),
    ], 11);

    private static void Dispose(List<ObjectAttribute> template)
    {
        foreach (ObjectAttribute attribute in template)
            attribute.Dispose();
    }

    /// <summary>
    /// No pointer was outside its block, and the template values the test passed all reached the module.
    /// The session may add its own (secure defaults such as <c>CKA_SENSITIVE</c>), so at least that many.
    /// </summary>
    private static void AssertTemplateInItsBlocks(AllocationBoundsModule module, string template, int values)
    {
        Assert.Empty(module.Violations);
        Assert.InRange(module.Checked.Count(c => c.StartsWith(template, StringComparison.Ordinal)), values, int.MaxValue);
    }

    /// <summary>No pointer was outside its block, and exactly these parameter pointers were checked.</summary>
    private static void AssertParametersInTheirBlocks(AllocationBoundsModule module, params string[] pointers)
    {
        Assert.Empty(module.Violations);
        Assert.Equal(
            ["mechanism parameter", .. pointers],
            module.Checked.Where(c => c.StartsWith("mechanism parameter", StringComparison.Ordinal) || c.StartsWith("CK_", StringComparison.Ordinal)));
    }

    // -----------------------------------------------------------------------
    // Templates
    // -----------------------------------------------------------------------

    public static TheoryData<string> TemplateCalls =>
        ["C_CreateObject", "C_CopyObject", "C_SetAttributeValue", "C_FindObjectsInit", "C_GenerateKey", "C_UnwrapKey"];

    [Theory]
    [MemberData(nameof(TemplateCalls))]
    public void Template_EveryValue_IsInItsBlock(string call)
    {
        using var module = new AllocationBoundsModule();
        using var session = module.CreateSession();
        (List<ObjectAttribute> template, int values) = EveryShape();
        try
        {
            switch (call)
            {
                case "C_CreateObject": session.CreateObject(template); break;
                case "C_CopyObject": session.CopyObject(Key, template); break;
                case "C_SetAttributeValue": session.SetAttributeValue(Key, template); break;
                case "C_FindObjectsInit": session.FindObjectsInit(template); break;
                case "C_GenerateKey": session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template); break;
                default: session.UnwrapKey(new Mechanism(CKM.CKM_AES_KEY_WRAP_PAD), Key, Bytes(40), template); break;
            }
        }
        finally { Dispose(template); }

        AssertTemplateInItsBlocks(module, $"{call} template", values);
    }

    [Fact]
    public void GenerateKeyPair_BothTemplates_AreInTheirBlocks()
    {
        using var module = new AllocationBoundsModule();
        using var session = module.CreateSession();
        (List<ObjectAttribute> publicTemplate, int publicValues) = EveryShape();
        (List<ObjectAttribute> privateTemplate, int privateValues) = EveryShape();
        try
        {
            session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), publicTemplate, privateTemplate, out _, out _);
        }
        finally
        {
            Dispose(publicTemplate);
            Dispose(privateTemplate);
        }

        AssertTemplateInItsBlocks(module, "C_GenerateKeyPair public template", publicValues);
        AssertTemplateInItsBlocks(module, "C_GenerateKeyPair private template", privateValues);
    }

    // The module writes each value it is lent to its full stated length.
    [Fact]
    public void GetAttributeValue_EveryValueBuffer_IsInItsBlock()
    {
        using var module = new AllocationBoundsModule();
        using var session = module.CreateSession();
        CKA[] requested = [CKA.CKA_LABEL, CKA.CKA_ID, CKA.CKA_VALUE];

        using var values = session.GetAttributeValue(Key, requested);

        AssertTemplateInItsBlocks(module, "C_GetAttributeValue value", requested.Length);
        Assert.All(values, v => Assert.Equal(AllocationBoundsModule.AttributeValueLength, v.GetValueAsByteArray()!.Length));
    }

    // -----------------------------------------------------------------------
    // Mechanism parameters: the block, then each buffer it points to
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData(1)]
    [InlineData(13)]
    [InlineData(4099)]
    public void Encrypt_GcmParameters_AreInTheirBlocks(int length)
    {
        using var module = new AllocationBoundsModule();
        using var session = module.CreateSession();

        session.Encrypt(new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(Bytes(Math.Min(length, 256)), Bytes(length), tagBits: 128)), Key, Bytes(16));

        AssertParametersInTheirBlocks(module, "CK_GCM_PARAMS.pIv", "CK_GCM_PARAMS.pAAD");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(13)]
    [InlineData(4099)]
    public void Encrypt_CcmParameters_AreInTheirBlocks(int length)
    {
        using var module = new AllocationBoundsModule();
        using var session = module.CreateSession();

        session.Encrypt(new Mechanism(CKM.CKM_AES_CCM, new CkmAesCcmParams(16, Bytes(13), Bytes(length), macLen: 16)), Key, Bytes(16));

        AssertParametersInTheirBlocks(module, "CK_CCM_PARAMS.pNonce", "CK_CCM_PARAMS.pAAD");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(13)]
    [InlineData(4099)]
    public void Encrypt_OaepParameters_AreInTheirBlocks(int length)
    {
        using var module = new AllocationBoundsModule();
        using var session = module.CreateSession();

        session.Encrypt(new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, Bytes(length))), Key, Bytes(16));

        AssertParametersInTheirBlocks(module, "CK_RSA_PKCS_OAEP_PARAMS.pSourceData");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(13)]
    [InlineData(4099)]
    public void DeriveKey_Ecdh1Parameters_AreInTheirBlocks(int length)
    {
        using var module = new AllocationBoundsModule();
        using var session = module.CreateSession();
        var parameters = new CkmEcdh1DeriveParams(CKD.CKD_SHA256_KDF, Bytes(65), Bytes(length));

        session.DeriveKey(new Mechanism(CKM.CKM_ECDH1_DERIVE, parameters), Key, []);

        AssertParametersInTheirBlocks(module, "CK_ECDH1_DERIVE_PARAMS.pSharedData", "CK_ECDH1_DERIVE_PARAMS.pPublicData");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(13)]
    [InlineData(4099)]
    public void DeriveKey_HkdfParameters_AreInTheirBlocks(int length)
    {
        using var module = new AllocationBoundsModule();
        using var session = module.CreateSession();
        var parameters = CkmHkdfParams.WithSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256, Bytes(length), Bytes(length));

        session.DeriveKey(new Mechanism(CKM.CKM_HKDF_DERIVE, parameters), Key, []);

        AssertParametersInTheirBlocks(module, "CK_HKDF_PARAMS.pSalt", "CK_HKDF_PARAMS.pInfo");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(13)]
    [InlineData(4099)]
    public void GenerateKey_Pbkdf2Parameters_AreInTheirBlocks(int length)
    {
        using var module = new AllocationBoundsModule();
        using var session = module.CreateSession();
        var parameters = new CkmPkcs5Pbkd2Params(Bytes(length), 1000, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, Bytes(length), Bytes(length));

        session.GenerateKey(new Mechanism(CKM.CKM_PKCS5_PBKD2, parameters), []);

        AssertParametersInTheirBlocks(
            module, "CK_PKCS5_PBKD2_PARAMS2.pSaltSourceData", "CK_PKCS5_PBKD2_PARAMS2.pPrfData", "CK_PKCS5_PBKD2_PARAMS2.pPassword");
    }

    // -----------------------------------------------------------------------
    // The oracle itself
    // -----------------------------------------------------------------------

    [Fact]
    public void TryFindAllocation_FindsEveryByteOfALiveBlock_AndNothingPastIt()
    {
        IntPtr block = UnmanagedMemory.Allocate(13);
        try
        {
            Assert.True(UnmanagedMemory.TryFindAllocation(block, out IntPtr start, out int size));
            Assert.Equal((block, 13), (start, size));
            Assert.True(UnmanagedMemory.TryFindAllocation(block + 12, out start, out _));
            Assert.Equal(block, start);
            Assert.False(UnmanagedMemory.TryFindAllocation(block + 13, out start, out _) && start == block);
        }
        finally
        {
            IntPtr freed = block;
            UnmanagedMemory.Free(ref block);
            Assert.False(UnmanagedMemory.TryFindAllocation(freed, out IntPtr start, out _) && start == freed);
        }
    }
}
