using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Dispatch;

/// <summary>
/// The object wrappers, called through a module's function table: each reaches the module with its
/// object handle and template (in the Pack=1 layout on Windows), returns the handles and lengths the module
/// writes, and refuses a search that reports more objects than it was given room for.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class ObjectDispatchTests
{
    private static readonly ulong[] TemplateTypes = [(ulong)CKA.CKA_CLASS, (ulong)CKA.CKA_LABEL];
    private const ulong Object = 0x42;
    private const ulong NewObject = 0x43;

    private static CK_ATTRIBUTE[] Template() =>
    [
        new() { type = (NativeCULong)(ulong)CKA.CKA_CLASS },
        new() { type = (NativeCULong)(ulong)CKA.CKA_LABEL },
    ];

    private static readonly Dictionary<string, DispatchCase> Cases = new DispatchCase[]
    {
        new(nameof(LowLevelPkcs11Library.C_CreateObject), l =>
        {
            NativeCULong id = default;
            CKR rv = l.C_CreateObject(DispatchSmoke.Session, Template(), ref id);
            return Returned(rv, id);
        }),
        new(nameof(LowLevelPkcs11Library.C_CopyObject), l =>
        {
            NativeCULong id = default;
            CKR rv = l.C_CopyObject(DispatchSmoke.Session, (NativeCULong)Object, Template(), ref id);
            return Returned(rv, id);
        }),
        new(nameof(LowLevelPkcs11Library.C_DestroyObject), l => l.C_DestroyObject(DispatchSmoke.Session, (NativeCULong)Object)),
        new(nameof(LowLevelPkcs11Library.C_GetObjectSize), l =>
        {
            NativeCULong size = default;
            CKR rv = l.C_GetObjectSize(DispatchSmoke.Session, (NativeCULong)Object, ref size);
            return Returned(rv, size);
        }),
        new(nameof(LowLevelPkcs11Library.C_GetAttributeValue), l => l.C_GetAttributeValue(DispatchSmoke.Session, (NativeCULong)Object, Template())),
        new(nameof(LowLevelPkcs11Library.C_SetAttributeValue), l => l.C_SetAttributeValue(DispatchSmoke.Session, (NativeCULong)Object, Template())),
        new(nameof(LowLevelPkcs11Library.C_FindObjectsInit), l => l.C_FindObjectsInit(DispatchSmoke.Session, Template())),
        new(nameof(LowLevelPkcs11Library.C_FindObjects), l =>
        {
            CKR rv = l.C_FindObjects(DispatchSmoke.Session, new NativeCULong[4], out NativeCULong count);
            return rv == CKR.CKR_OK && (ulong)count != 2 ? CKR.CKR_GENERAL_ERROR : rv;
        }),
        new(nameof(LowLevelPkcs11Library.C_FindObjectsFinal), l => l.C_FindObjectsFinal(DispatchSmoke.Session)),
    }.ToDictionary(c => c.Function, StringComparer.Ordinal);

    public static TheoryData<string> Functions => [.. Cases.Keys];

    private static readonly HashSet<string> TakesTemplate =
    [
        nameof(LowLevelPkcs11Library.C_CreateObject), nameof(LowLevelPkcs11Library.C_CopyObject), nameof(LowLevelPkcs11Library.C_GetAttributeValue),
        nameof(LowLevelPkcs11Library.C_SetAttributeValue), nameof(LowLevelPkcs11Library.C_FindObjectsInit),
    ];

    private static readonly HashSet<string> TakesObject =
    [
        nameof(LowLevelPkcs11Library.C_CopyObject), nameof(LowLevelPkcs11Library.C_DestroyObject), nameof(LowLevelPkcs11Library.C_GetObjectSize),
        nameof(LowLevelPkcs11Library.C_GetAttributeValue), nameof(LowLevelPkcs11Library.C_SetAttributeValue),
    ];

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_ReachesTheModule_WithItsArguments_AndReturnsItsResults(string function)
    {
        using var module = new ObjectModule();

        Assert.Equal(CKR.CKR_OK, DispatchSmoke.ReachesTheModule(module, Cases[function]));

        Assert.Equal((ulong)DispatchSmoke.Session, (ulong)module.LastSession);
        if (TakesTemplate.Contains(function))
            Assert.Equal(TemplateTypes, module.LastTemplate);
        if (TakesObject.Contains(function))
            Assert.Equal(Object, module.LastObject);
    }

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_OfAFunctionTheModuleLacks_ReturnsNotSupported(string function)
        => DispatchSmoke.ReportsAMissingFunctionUnsupported(Cases[function]);

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_AfterDispose_Throws_WithoutReachingTheModule(string function)
    {
        using var module = new ObjectModule();
        DispatchSmoke.RefusesACallAfterDispose(module, Cases[function]);
    }

    // On Windows the module writes into a packed copy of the template; the lengths it reports must still
    // reach the caller's template.
    [Fact]
    public void GetAttributeValue_ReturnsTheLengthsTheModuleWrote()
    {
        using var module = new ObjectModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        CK_ATTRIBUTE[] template = Template();

        Assert.Equal(CKR.CKR_OK, lowLevel.C_GetAttributeValue(DispatchSmoke.Session, (NativeCULong)Object, template));

        Assert.Equal([8UL, 5UL], template.Select(a => (ulong)a.valueLen));
    }

    [Fact]
    public void FindObjects_ReportingMoreObjectsThanTheBufferHolds_IsRefused()
    {
        using var module = new ObjectModule { OverReports = true };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Throws<Pkcs11UnclassifiedException>(() => lowLevel.C_FindObjects(DispatchSmoke.Session, new NativeCULong[4], out _));
    }

    // A call that writes back a handle or size succeeds only if the module's value came back.
    private static CKR Returned(CKR rv, NativeCULong value) => rv == CKR.CKR_OK && (ulong)value != NewObject ? CKR.CKR_GENERAL_ERROR : rv;

    /// <summary>Implements the whole object family and records what each call received.</summary>
    private sealed class ObjectModule : FakeModule
    {
        public bool OverReports { get; init; }

        public NativeCULong LastSession { get; private set; }
        public ulong LastObject { get; private set; }
        public ulong[]? LastTemplate { get; private set; }

        protected override CKR C_CreateObject(NativeCULong session, CK_ATTRIBUTE[] template, ref NativeCULong objectId)
        {
            Received(session, default, template);
            objectId = (NativeCULong)NewObject;
            return CKR.CKR_OK;
        }

        protected override CKR C_CopyObject(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, ref NativeCULong newObjectId)
        {
            Received(session, objectId, template);
            newObjectId = (NativeCULong)NewObject;
            return CKR.CKR_OK;
        }

        protected override CKR C_DestroyObject(NativeCULong session, NativeCULong objectId) => Received(session, objectId, null);

        protected override CKR C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size)
        {
            size = (NativeCULong)NewObject;
            return Received(session, objectId, null);
        }

        protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
        {
            Received(session, objectHandle, template.ToArray());
            for (int i = 0; i < template.Length; i++)
                template[i].valueLen = (NativeCULong)(ulong)(i == 0 ? 8 : 5);
            return CKR.CKR_OK;
        }

        protected override CKR C_SetAttributeValue(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template)
            => Received(session, objectId, template);

        protected override CKR C_FindObjectsInit(NativeCULong session, CK_ATTRIBUTE[] template) => Received(session, default, template);

        protected override CKR C_FindObjects(NativeCULong session, Span<NativeCULong> objects, ref NativeCULong count)
        {
            LastSession = session;
            objects[0] = (NativeCULong)1;
            objects[1] = (NativeCULong)2;
            count = (NativeCULong)(ulong)(OverReports ? objects.Length + 1 : 2);
            return CKR.CKR_OK;
        }

        protected override CKR C_FindObjectsFinal(NativeCULong session) => Received(session, default, null);

        private CKR Received(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[]? template)
        {
            LastSession = session;
            LastObject = (ulong)objectId;
            if (template is not null)
                LastTemplate = [.. template.Select(a => (ulong)a.type)];
            return CKR.CKR_OK;
        }
    }
}
