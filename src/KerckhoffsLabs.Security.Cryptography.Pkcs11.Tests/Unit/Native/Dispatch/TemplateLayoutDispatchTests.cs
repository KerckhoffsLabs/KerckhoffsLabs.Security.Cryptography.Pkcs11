using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Dispatch;

/// <summary>
/// An attribute template is laid out on the stack when it fits <see cref="NativeStructArray.StackBytes"/>
/// and on the native heap when it does not. Both must reach the module intact, and what the module writes
/// back into the template must reach the caller.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class TemplateLayoutDispatchTests
{
    private static readonly int FitsOnTheStack = NativeStructArray.StackBytes / Pkcs11Marshal.SizeOf<CK_ATTRIBUTE>();

    public static TheoryData<int> TemplateSizes => [1, FitsOnTheStack, FitsOnTheStack + 1, 3 * FitsOnTheStack];

    [Theory]
    [MemberData(nameof(TemplateSizes))]
    public void CreateObject_HandsTheModuleTheWholeTemplate(int attributes)
    {
        using var module = new TemplateModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        NativeCULong objectId = default;

        Assert.Equal(CKR.CKR_OK, lowLevel.C_CreateObject(DispatchSmoke.Session, Template(attributes), ref objectId));

        Assert.Equal(Enumerable.Range(0, attributes).Select(i => (ulong)i), module.LastTypes);
    }

    [Theory]
    [MemberData(nameof(TemplateSizes))]
    public void GetAttributeValue_ReturnsTheLengthsTheModuleWrote(int attributes)
    {
        using var module = new TemplateModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        CK_ATTRIBUTE[] template = Template(attributes);

        Assert.Equal(CKR.CKR_OK, lowLevel.C_GetAttributeValue(DispatchSmoke.Session, (NativeCULong)1, template));

        Assert.Equal(Enumerable.Range(0, attributes).Select(i => (ulong)(i + 100)), template.Select(a => (ulong)a.valueLen));
    }

    // The point of the stack layout: a call with an ordinary template makes no native allocation.
    [Fact]
    public void CreateObject_WithATemplateThatFitsTheStack_AllocatesNoNativeMemory()
    {
        using var module = new TemplateModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        CK_ATTRIBUTE[] template = Template(8);
        NativeCULong objectId = default;
        int before = UnmanagedMemory.ThreadAllocationCount;

        lowLevel.C_CreateObject(DispatchSmoke.Session, template, ref objectId);

        Assert.Equal(before, UnmanagedMemory.ThreadAllocationCount);
    }

    private static CK_ATTRIBUTE[] Template(int attributes)
        => [.. Enumerable.Range(0, attributes).Select(i => new CK_ATTRIBUTE { type = (NativeCULong)(ulong)i })];

    private sealed class TemplateModule : FakeModule
    {
        public ulong[]? LastTypes { get; private set; }

        protected override CKR C_CreateObject(NativeCULong session, CK_ATTRIBUTE[] template, ref NativeCULong objectId)
        {
            LastTypes = [.. template.Select(a => (ulong)a.type)];
            objectId = (NativeCULong)1;
            return CKR.CKR_OK;
        }

        protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
        {
            for (int i = 0; i < template.Length; i++)
                template[i].valueLen = (NativeCULong)(ulong)(i + 100);
            return CKR.CKR_OK;
        }
    }
}
