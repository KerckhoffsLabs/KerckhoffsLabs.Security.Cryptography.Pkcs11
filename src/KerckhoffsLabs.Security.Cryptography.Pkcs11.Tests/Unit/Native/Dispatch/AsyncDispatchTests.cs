using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Dispatch;

/// <summary>
/// The v3.2 asynchronous-operation wrappers, called through a module's function table: each reaches the
/// module with its function name, identifier and data, and returns what the module writes, across the
/// Windows struct packing.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class AsyncDispatchTests
{
    private static readonly byte[] FunctionName = "C_Sign\0"u8.ToArray();
    private static readonly byte[] Data = [0x0D, 0x0A];
    private const ulong Id = 0x77;

    private static readonly Dictionary<string, DispatchCase> Cases = new DispatchCase[]
    {
        new(nameof(LowLevelPkcs11Library.C_AsyncComplete), l =>
        {
            CK_ASYNC_DATA result = new() { Version = (NativeCULong)1 };
            CKR rv = l.C_AsyncComplete(DispatchSmoke.Session, FunctionName, ref result);
            return rv == CKR.CKR_OK && ((ulong)result.Object != Id || (ulong)result.ValueLen != 5) ? CKR.CKR_GENERAL_ERROR : rv;
        }),
        new(nameof(LowLevelPkcs11Library.C_AsyncGetID), l =>
        {
            NativeCULong id = default;
            CKR rv = l.C_AsyncGetID(DispatchSmoke.Session, FunctionName, ref id);
            return rv == CKR.CKR_OK && (ulong)id != Id ? CKR.CKR_GENERAL_ERROR : rv;
        }),
        new(nameof(LowLevelPkcs11Library.C_AsyncJoin), l => l.C_AsyncJoin(DispatchSmoke.Session, FunctionName, (NativeCULong)Id, Data)),
    }.ToDictionary(c => c.Function, StringComparer.Ordinal);

    public static TheoryData<string> Functions => [.. Cases.Keys];

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_ReachesTheModule_AndReturnsWhatItWrites(string function)
    {
        using var module = new AsyncModule();

        Assert.Equal(CKR.CKR_OK, DispatchSmoke.ReachesTheModule(module, Cases[function]));

        Assert.Equal((ulong)DispatchSmoke.Session, (ulong)module.LastSession);
        Assert.Equal("C_Sign", module.LastFunctionName);
    }

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_OfAFunctionTheModuleLacks_ReturnsNotSupported(string function)
        => DispatchSmoke.ReportsAMissingFunctionUnsupported(Cases[function]);

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_AfterDispose_Throws_WithoutReachingTheModule(string function)
    {
        using var module = new AsyncModule();
        DispatchSmoke.RefusesACallAfterDispose(module, Cases[function]);
    }

    // On Windows the module works on a packed copy; it must start from the caller's values there too.
    [Fact]
    public void AsyncComplete_PassesTheCallersValuesToTheModule()
    {
        using var module = new AsyncModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        CK_ASYNC_DATA result = new() { Version = (NativeCULong)1 };

        lowLevel.C_AsyncComplete(DispatchSmoke.Session, FunctionName, ref result);

        Assert.Equal(1UL, module.VersionSeen);
    }

    [Fact]
    public void AsyncJoin_PassesTheIdAndData()
    {
        using var module = new AsyncModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        lowLevel.C_AsyncJoin(DispatchSmoke.Session, FunctionName, (NativeCULong)Id, Data);

        Assert.Equal(Id, module.LastId);
        Assert.Equal(Data, module.LastData);
    }

    private sealed class AsyncModule : FakeModule
    {
        public NativeCULong LastSession { get; private set; }
        public string? LastFunctionName { get; private set; }
        public ulong LastId { get; private set; }
        public byte[]? LastData { get; private set; }
        public ulong VersionSeen { get; private set; }

        protected override CKR C_AsyncComplete(NativeCULong session, string functionName, ref CK_ASYNC_DATA result)
        {
            Received(session, functionName);
            VersionSeen = (ulong)result.Version;
            result.Object = (NativeCULong)Id;
            result.ValueLen = (NativeCULong)5;
            return CKR.CKR_OK;
        }

        protected override CKR C_AsyncGetID(NativeCULong session, string functionName, ref NativeCULong id)
        {
            Received(session, functionName);
            id = (NativeCULong)Id;
            return CKR.CKR_OK;
        }

        protected override CKR C_AsyncJoin(NativeCULong session, string functionName, NativeCULong id, ReadOnlySpan<byte> data)
        {
            Received(session, functionName);
            LastId = (ulong)id;
            LastData = data.ToArray();
            return CKR.CKR_OK;
        }

        private void Received(NativeCULong session, string functionName)
        {
            LastSession = session;
            LastFunctionName = functionName;
        }
    }
}
