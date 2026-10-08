using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Dispatch;

/// <summary>
/// The legacy parallel-function wrappers, called through a module's function table: each reaches the
/// module and returns its answer, which for a v2.40 module is <c>CKR_FUNCTION_NOT_PARALLEL</c>.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class ParallelFunctionDispatchTests
{
    private static readonly Dictionary<string, DispatchCase> Cases = new DispatchCase[]
    {
        new(nameof(LowLevelPkcs11Library.C_GetFunctionStatus), l => l.C_GetFunctionStatus(DispatchSmoke.Session)),
        new(nameof(LowLevelPkcs11Library.C_CancelFunction), l => l.C_CancelFunction(DispatchSmoke.Session)),
    }.ToDictionary(c => c.Function, StringComparer.Ordinal);

    public static TheoryData<string> Functions => [.. Cases.Keys];

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_ReachesTheModule_AndReturnsItsAnswer(string function)
    {
        using var module = new ParallelModule();

        Assert.Equal(CKR.CKR_FUNCTION_NOT_PARALLEL, DispatchSmoke.ReachesTheModule(module, Cases[function]));
        Assert.Equal((ulong)DispatchSmoke.Session, (ulong)module.LastSession);
    }

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_OfAFunctionTheModuleLacks_ReturnsNotSupported(string function)
        => DispatchSmoke.ReportsAMissingFunctionUnsupported(Cases[function]);

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_AfterDispose_Throws_WithoutReachingTheModule(string function)
    {
        using var module = new ParallelModule();
        DispatchSmoke.RefusesACallAfterDispose(module, Cases[function]);
    }

    private sealed class ParallelModule : FakeModule
    {
        public NativeCULong LastSession { get; private set; }

        protected override CKR C_GetFunctionStatus(NativeCULong session) => Answer(session);
        protected override CKR C_CancelFunction(NativeCULong session) => Answer(session);

        private CKR Answer(NativeCULong session)
        {
            LastSession = session;
            return CKR.CKR_FUNCTION_NOT_PARALLEL;
        }
    }
}
