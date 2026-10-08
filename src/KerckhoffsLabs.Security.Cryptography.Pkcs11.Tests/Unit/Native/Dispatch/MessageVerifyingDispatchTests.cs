using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Dispatch;

/// <summary>
/// The v3.0 message-based verification wrappers, called through a module's function table: each reaches the
/// module with its per-message parameter, data and signature, and returns the module's verdict.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class MessageVerifyingDispatchTests
{
    private static readonly byte[] Data = [0x0D, 0x0A, 0x7A];
    private static readonly byte[] Signature = [0x51, 0x52, 0x53, 0x54];
    private static readonly IntPtr Parameter = (IntPtr)0x1000;
    private const ulong ParameterLength = 40;

    private static readonly Dictionary<string, DispatchCase> Cases = new DispatchCase[]
    {
        new(nameof(LowLevelPkcs11Library.C_MessageVerifyInit), l => { CK_MECHANISM m = Mechanism(); return l.C_MessageVerifyInit(DispatchSmoke.Session, ref m, (NativeCULong)3); }),
        new(nameof(LowLevelPkcs11Library.C_VerifyMessage), l => l.C_VerifyMessage(DispatchSmoke.Session, Parameter, (NativeCULong)ParameterLength, Data, Signature)),
        new(nameof(LowLevelPkcs11Library.C_VerifyMessageBegin), l => l.C_VerifyMessageBegin(DispatchSmoke.Session, Parameter, (NativeCULong)ParameterLength)),
        new(nameof(LowLevelPkcs11Library.C_VerifyMessageNext), l => l.C_VerifyMessageNext(DispatchSmoke.Session, Parameter, (NativeCULong)ParameterLength, Data, Signature)),
        new(nameof(LowLevelPkcs11Library.C_MessageVerifyFinal), l => l.C_MessageVerifyFinal(DispatchSmoke.Session)),
    }.ToDictionary(c => c.Function, StringComparer.Ordinal);

    public static TheoryData<string> Functions => [.. Cases.Keys];

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_ReachesTheModule_WithItsArguments(string function)
    {
        using var module = new VerifyingModule();

        Assert.Equal(CKR.CKR_OK, DispatchSmoke.ReachesTheModule(module, Cases[function]));

        Assert.Equal((ulong)DispatchSmoke.Session, (ulong)module.LastSession);
        if (function == nameof(LowLevelPkcs11Library.C_MessageVerifyInit))
            Assert.Equal((ulong)CKM.CKM_ECDSA, module.LastMechanism);
        if (function is nameof(LowLevelPkcs11Library.C_VerifyMessage) or nameof(LowLevelPkcs11Library.C_VerifyMessageBegin) or nameof(LowLevelPkcs11Library.C_VerifyMessageNext))
            Assert.Equal((Parameter, ParameterLength), (module.LastParameter, module.LastParameterLength));
        if (function is nameof(LowLevelPkcs11Library.C_VerifyMessage) or nameof(LowLevelPkcs11Library.C_VerifyMessageNext))
        {
            Assert.Equal(Data, module.LastData);
            Assert.Equal(Signature, module.LastSignature);
        }
    }

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_OfAFunctionTheModuleLacks_ReturnsNotSupported(string function)
        => DispatchSmoke.ReportsAMissingFunctionUnsupported(Cases[function]);

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_AfterDispose_Throws_WithoutReachingTheModule(string function)
    {
        using var module = new VerifyingModule();
        DispatchSmoke.RefusesACallAfterDispose(module, Cases[function]);
    }

    [Fact]
    public void VerifyMessage_ReturnsTheModulesVerdict()
    {
        using var module = new VerifyingModule { Verdict = CKR.CKR_SIGNATURE_INVALID };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Equal(CKR.CKR_SIGNATURE_INVALID, Cases[nameof(LowLevelPkcs11Library.C_VerifyMessage)].Invoke(lowLevel));
    }

    private static CK_MECHANISM Mechanism() => new() { Mechanism = (NativeCULong)(ulong)CKM.CKM_ECDSA };

    private sealed class VerifyingModule : FakeModule
    {
        public CKR Verdict { get; init; } = CKR.CKR_OK;

        public NativeCULong LastSession { get; private set; }
        public ulong LastMechanism { get; private set; }
        public IntPtr LastParameter { get; private set; }
        public ulong LastParameterLength { get; private set; }
        public byte[]? LastData { get; private set; }
        public byte[]? LastSignature { get; private set; }

        protected override CKR C_MessageVerifyInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        {
            LastSession = session;
            LastMechanism = (ulong)mechanism.Mechanism;
            return CKR.CKR_OK;
        }

        protected override CKR C_VerifyMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
            => Checked(session, parameter, parameterLen, data, signature);

        protected override CKR C_VerifyMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen)
        {
            Received(session, parameter, parameterLen);
            return CKR.CKR_OK;
        }

        protected override CKR C_VerifyMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
            => Checked(session, parameter, parameterLen, data, signature);

        protected override CKR C_MessageVerifyFinal(NativeCULong session)
        {
            LastSession = session;
            return CKR.CKR_OK;
        }

        private void Received(NativeCULong session, IntPtr parameter, NativeCULong parameterLen)
        {
            LastSession = session;
            LastParameter = parameter;
            LastParameterLength = (ulong)parameterLen;
        }

        private CKR Checked(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            Received(session, parameter, parameterLen);
            LastData = data.ToArray();
            LastSignature = signature.ToArray();
            return Verdict;
        }
    }
}
