using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Dispatch;

/// <summary>
/// The v3.0 message-based signing wrappers, called through a module's function table: each reaches the
/// module with its per-message parameter and data, and the two that return a signature follow the output
/// rules of PKCS#11 v3.2 §5.2.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class MessageSigningDispatchTests
{
    private static readonly byte[] Data = [0x0D, 0x0A, 0x7A];
    private static readonly byte[] Signature = [0x51, 0x52, 0x53, 0x54];
    private static readonly IntPtr Parameter = (IntPtr)0x1000;
    private const ulong ParameterLength = 40;

    private static readonly Dictionary<string, DispatchCase> Cases = new DispatchCase[]
    {
        new(nameof(LowLevelPkcs11Library.C_MessageSignInit), l => { CK_MECHANISM m = Mechanism(); return l.C_MessageSignInit(DispatchSmoke.Session, ref m, (NativeCULong)3); }),
        new(nameof(LowLevelPkcs11Library.C_SignMessage), l => l.C_SignMessage(DispatchSmoke.Session, Parameter, (NativeCULong)ParameterLength, Data, new byte[8], lengthOnly: false, out _)),
        new(nameof(LowLevelPkcs11Library.C_SignMessageBegin), l => l.C_SignMessageBegin(DispatchSmoke.Session, Parameter, (NativeCULong)ParameterLength)),
        new(nameof(LowLevelPkcs11Library.C_SignMessageNext), l => l.C_SignMessageNext(DispatchSmoke.Session, Parameter, (NativeCULong)ParameterLength, Data, new byte[8], lengthOnly: false, out _)),
        new(nameof(LowLevelPkcs11Library.C_MessageSignFinal), l => l.C_MessageSignFinal(DispatchSmoke.Session)),
    }.ToDictionary(c => c.Function, StringComparer.Ordinal);

    public static TheoryData<string> Functions => [.. Cases.Keys];

    private static readonly Dictionary<string, OutputCall> Outputs = new(StringComparer.Ordinal)
    {
        [nameof(LowLevelPkcs11Library.C_SignMessage)] = (LowLevelPkcs11Library l, Span<byte> output, bool lengthOnly, out NativeCULong length)
            => l.C_SignMessage(DispatchSmoke.Session, Parameter, (NativeCULong)ParameterLength, Data, output, lengthOnly, out length),
        [nameof(LowLevelPkcs11Library.C_SignMessageNext)] = (LowLevelPkcs11Library l, Span<byte> output, bool lengthOnly, out NativeCULong length)
            => l.C_SignMessageNext(DispatchSmoke.Session, Parameter, (NativeCULong)ParameterLength, Data, output, lengthOnly, out length),
    };

    public static TheoryData<string> OutputFunctions => [.. Outputs.Keys];

    private delegate CKR OutputCall(LowLevelPkcs11Library lowLevel, Span<byte> output, bool lengthOnly, out NativeCULong length);

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_ReachesTheModule_WithItsArguments(string function)
    {
        using var module = new SigningModule();

        Assert.Equal(CKR.CKR_OK, DispatchSmoke.ReachesTheModule(module, Cases[function]));

        Assert.Equal((ulong)DispatchSmoke.Session, (ulong)module.LastSession);
        if (function == nameof(LowLevelPkcs11Library.C_MessageSignInit))
            Assert.Equal((ulong)CKM.CKM_ECDSA, module.LastMechanism);
        if (function is nameof(LowLevelPkcs11Library.C_SignMessage) or nameof(LowLevelPkcs11Library.C_SignMessageBegin) or nameof(LowLevelPkcs11Library.C_SignMessageNext))
            Assert.Equal((Parameter, ParameterLength), (module.LastParameter, module.LastParameterLength));
        if (function is nameof(LowLevelPkcs11Library.C_SignMessage) or nameof(LowLevelPkcs11Library.C_SignMessageNext))
            Assert.Equal(Data, module.LastData);
    }

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_OfAFunctionTheModuleLacks_ReturnsNotSupported(string function)
        => DispatchSmoke.ReportsAMissingFunctionUnsupported(Cases[function]);

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_AfterDispose_Throws_WithoutReachingTheModule(string function)
    {
        using var module = new SigningModule();
        DispatchSmoke.RefusesACallAfterDispose(module, Cases[function]);
    }

    [Theory]
    [MemberData(nameof(OutputFunctions))]
    public void LengthQuery_SendsNoBuffer_AndReturnsTheLength(string function)
    {
        using var module = new SigningModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        CKR rv = Outputs[function](lowLevel, new byte[16], lengthOnly: true, out NativeCULong length);

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.True(module.OutputWasNull);
        Assert.Equal((ulong)Signature.Length, (ulong)length);
    }

    [Theory]
    [MemberData(nameof(OutputFunctions))]
    public void Fill_WritesTheSignature_AndReportsItsLength(string function)
    {
        using var module = new SigningModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        byte[] output = new byte[16];

        CKR rv = Outputs[function](lowLevel, output, lengthOnly: false, out NativeCULong length);

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.False(module.OutputWasNull);
        Assert.Equal(Signature, output.AsSpan(0, (int)(ulong)length).ToArray());
    }

    [Theory]
    [MemberData(nameof(OutputFunctions))]
    public void Fill_IntoAnEmptyBuffer_IsNotALengthQuery(string function)
    {
        using var module = new SigningModule { Produces = [] };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        CKR rv = Outputs[function](lowLevel, [], lengthOnly: false, out NativeCULong length);

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.False(module.OutputWasNull);
        Assert.Equal(0UL, (ulong)length);
    }

    [Theory]
    [MemberData(nameof(OutputFunctions))]
    public void Fill_ReportingMoreThanTheBuffer_IsRefused(string function)
    {
        using var module = new SigningModule { OverReports = true };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Throws<Pkcs11UnclassifiedException>(() => Outputs[function](lowLevel, new byte[16], lengthOnly: false, out _));
    }

    [Theory]
    [MemberData(nameof(OutputFunctions))]
    public void LengthQuery_ReportingUnavailableInformation_IsRefused(string function)
    {
        using var module = new SigningModule { QueryReports = NativeCULong.MaxValue };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Throws<Pkcs11UnclassifiedException>(() => Outputs[function](lowLevel, default, lengthOnly: true, out _));
    }

    private static CK_MECHANISM Mechanism() => new() { Mechanism = (NativeCULong)(ulong)CKM.CKM_ECDSA };

    private sealed class SigningModule : FakeModule
    {
        public byte[] Produces { get; init; } = Signature;
        public bool OverReports { get; init; }
        public NativeCULong? QueryReports { get; init; }

        public NativeCULong LastSession { get; private set; }
        public ulong LastMechanism { get; private set; }
        public IntPtr LastParameter { get; private set; }
        public ulong LastParameterLength { get; private set; }
        public byte[]? LastData { get; private set; }
        public bool OutputWasNull { get; private set; }

        protected override CKR C_MessageSignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        {
            LastSession = session;
            LastMechanism = (ulong)mechanism.Mechanism;
            return CKR.CKR_OK;
        }

        protected override CKR C_SignMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
            NativeBuffer<byte> signature, ref NativeCULong signatureLen)
            => Output(session, parameter, parameterLen, data, signature, ref signatureLen);

        protected override CKR C_SignMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen)
            => Received(session, parameter, parameterLen);

        protected override CKR C_SignMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
            NativeBuffer<byte> signature, ref NativeCULong signatureLen)
            => Output(session, parameter, parameterLen, data, signature, ref signatureLen);

        protected override CKR C_MessageSignFinal(NativeCULong session)
        {
            LastSession = session;
            return CKR.CKR_OK;
        }

        private CKR Received(NativeCULong session, IntPtr parameter, NativeCULong parameterLen)
        {
            LastSession = session;
            LastParameter = parameter;
            LastParameterLength = (ulong)parameterLen;
            return CKR.CKR_OK;
        }

        private CKR Output(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, NativeBuffer<byte> output, ref NativeCULong length)
        {
            Received(session, parameter, parameterLen);
            LastData = data.ToArray();
            OutputWasNull = output.IsNull;
            if (output.IsNull)
            {
                length = QueryReports ?? (NativeCULong)(ulong)Produces.Length;
                return CKR.CKR_OK;
            }
            if (output.Span.Length < Produces.Length)
            {
                length = (NativeCULong)(ulong)Produces.Length;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }
            Produces.CopyTo(output.Span);
            length = (NativeCULong)(ulong)(OverReports ? output.Span.Length + 1 : Produces.Length);
            return CKR.CKR_OK;
        }
    }
}
