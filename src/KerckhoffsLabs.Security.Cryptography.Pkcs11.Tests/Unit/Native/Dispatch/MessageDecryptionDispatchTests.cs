using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Dispatch;

/// <summary>
/// The v3.0 message-based decryption wrappers, called through a module's function table: each reaches the
/// module with its per-message parameter, associated data and input, and the one-shot and per-part calls
/// follow the output rules of PKCS#11 v3.2 §5.2.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class MessageDecryptionDispatchTests
{
    private static readonly byte[] AssociatedData = [0xAD, 0xAD];
    private static readonly byte[] Input = [0x0D, 0x0A, 0x7A];
    private static readonly byte[] Produced = [0x51, 0x52, 0x53, 0x54];
    private static readonly IntPtr Parameter = (IntPtr)0x1000;
    private const ulong ParameterLength = 40;

    private static readonly Dictionary<string, DispatchCase> Cases = new DispatchCase[]
    {
        new(nameof(LowLevelPkcs11Library.C_MessageDecryptInit), l => { CK_MECHANISM m = Mechanism(); return l.C_MessageDecryptInit(DispatchSmoke.Session, ref m, (NativeCULong)3); }),
        new(nameof(LowLevelPkcs11Library.C_DecryptMessage), l => l.C_DecryptMessage(DispatchSmoke.Session, Parameter, (NativeCULong)ParameterLength, AssociatedData, Input, new byte[8], lengthOnly: false, out _)),
        new(nameof(LowLevelPkcs11Library.C_DecryptMessageBegin), l => l.C_DecryptMessageBegin(DispatchSmoke.Session, Parameter, (NativeCULong)ParameterLength, AssociatedData)),
        new(nameof(LowLevelPkcs11Library.C_DecryptMessageNext), l => l.C_DecryptMessageNext(DispatchSmoke.Session, Parameter, (NativeCULong)ParameterLength, Input, new byte[8], lengthOnly: false, out _, (NativeCULong)0)),
        new(nameof(LowLevelPkcs11Library.C_MessageDecryptFinal), l => l.C_MessageDecryptFinal(DispatchSmoke.Session)),
    }.ToDictionary(c => c.Function, StringComparer.Ordinal);

    public static TheoryData<string> Functions => [.. Cases.Keys];

    private static readonly Dictionary<string, OutputCall> Outputs = new(StringComparer.Ordinal)
    {
        [nameof(LowLevelPkcs11Library.C_DecryptMessage)] = (LowLevelPkcs11Library l, Span<byte> output, bool lengthOnly, out NativeCULong length)
            => l.C_DecryptMessage(DispatchSmoke.Session, Parameter, (NativeCULong)ParameterLength, AssociatedData, Input, output, lengthOnly, out length),
        [nameof(LowLevelPkcs11Library.C_DecryptMessageNext)] = (LowLevelPkcs11Library l, Span<byte> output, bool lengthOnly, out NativeCULong length)
            => l.C_DecryptMessageNext(DispatchSmoke.Session, Parameter, (NativeCULong)ParameterLength, Input, output, lengthOnly, out length, (NativeCULong)0),
    };

    public static TheoryData<string> OutputFunctions => [.. Outputs.Keys];

    private delegate CKR OutputCall(LowLevelPkcs11Library lowLevel, Span<byte> output, bool lengthOnly, out NativeCULong length);

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_ReachesTheModule_WithItsArguments(string function)
    {
        using var module = new MessageModule();

        Assert.Equal(CKR.CKR_OK, DispatchSmoke.ReachesTheModule(module, Cases[function]));

        Assert.Equal((ulong)DispatchSmoke.Session, (ulong)module.LastSession);
        if (function == nameof(LowLevelPkcs11Library.C_MessageDecryptInit))
            Assert.Equal((ulong)CKM.CKM_AES_GCM, module.LastMechanism);
        if (function is nameof(LowLevelPkcs11Library.C_DecryptMessage) or nameof(LowLevelPkcs11Library.C_DecryptMessageBegin) or nameof(LowLevelPkcs11Library.C_DecryptMessageNext))
            Assert.Equal((Parameter, ParameterLength), (module.LastParameter, module.LastParameterLength));
        if (function is nameof(LowLevelPkcs11Library.C_DecryptMessage) or nameof(LowLevelPkcs11Library.C_DecryptMessageBegin))
            Assert.Equal(AssociatedData, module.LastAssociatedData);
        if (function is nameof(LowLevelPkcs11Library.C_DecryptMessage) or nameof(LowLevelPkcs11Library.C_DecryptMessageNext))
            Assert.Equal(Input, module.LastInput);
    }

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_OfAFunctionTheModuleLacks_ReturnsNotSupported(string function)
        => DispatchSmoke.ReportsAMissingFunctionUnsupported(Cases[function]);

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_AfterDispose_Throws_WithoutReachingTheModule(string function)
    {
        using var module = new MessageModule();
        DispatchSmoke.RefusesACallAfterDispose(module, Cases[function]);
    }

    [Theory]
    [MemberData(nameof(OutputFunctions))]
    public void LengthQuery_SendsNoBuffer_AndReturnsTheLength(string function)
    {
        using var module = new MessageModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        CKR rv = Outputs[function](lowLevel, new byte[16], lengthOnly: true, out NativeCULong length);

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.True(module.OutputWasNull);
        Assert.Equal((ulong)Produced.Length, (ulong)length);
    }

    [Theory]
    [MemberData(nameof(OutputFunctions))]
    public void Fill_WritesTheOutput_AndReportsItsLength(string function)
    {
        using var module = new MessageModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        byte[] output = new byte[16];

        CKR rv = Outputs[function](lowLevel, output, lengthOnly: false, out NativeCULong length);

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.False(module.OutputWasNull);
        Assert.Equal(Produced, output.AsSpan(0, (int)(ulong)length).ToArray());
    }

    // An empty output is a real one, such as the decryption of an empty message under an AEAD whose tag lives
    // in the parameter: sent as NULL, it would be a second length query.
    [Theory]
    [MemberData(nameof(OutputFunctions))]
    public void Fill_IntoAnEmptyBuffer_IsNotALengthQuery(string function)
    {
        using var module = new MessageModule { Produces = [] };
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
        using var module = new MessageModule { OverReports = true };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Throws<Pkcs11UnclassifiedException>(() => Outputs[function](lowLevel, new byte[16], lengthOnly: false, out _));
    }

    [Theory]
    [MemberData(nameof(OutputFunctions))]
    public void LengthQuery_ReportingUnavailableInformation_IsRefused(string function)
    {
        using var module = new MessageModule { QueryReports = NativeCULong.MaxValue };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Throws<Pkcs11UnclassifiedException>(() => Outputs[function](lowLevel, default, lengthOnly: true, out _));
    }

    private static CK_MECHANISM Mechanism() => new() { Mechanism = (NativeCULong)(ulong)CKM.CKM_AES_GCM };

    /// <summary>Implements the whole family, records what each call received, and answers output calls.</summary>
    private sealed class MessageModule : FakeModule
    {
        public byte[] Produces { get; init; } = Produced;
        public bool OverReports { get; init; }
        public NativeCULong? QueryReports { get; init; }

        public NativeCULong LastSession { get; private set; }
        public ulong LastMechanism { get; private set; }
        public IntPtr LastParameter { get; private set; }
        public ulong LastParameterLength { get; private set; }
        public byte[]? LastAssociatedData { get; private set; }
        public byte[]? LastInput { get; private set; }
        public bool OutputWasNull { get; private set; }

        protected override CKR C_MessageDecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        {
            LastSession = session;
            LastMechanism = (ulong)mechanism.Mechanism;
            return CKR.CKR_OK;
        }

        protected override CKR C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> input, NativeBuffer<byte> output, ref NativeCULong length)
        {
            LastAssociatedData = associatedData.ToArray();
            return Output(session, parameter, parameterLen, input, output, ref length);
        }

        protected override CKR C_DecryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData)
        {
            LastAssociatedData = associatedData.ToArray();
            return Received(session, parameter, parameterLen);
        }

        protected override CKR C_DecryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> input,
            NativeBuffer<byte> output, ref NativeCULong length, NativeCULong flags)
            => Output(session, parameter, parameterLen, input, output, ref length);

        protected override CKR C_MessageDecryptFinal(NativeCULong session)
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

        private CKR Output(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> input, NativeBuffer<byte> output, ref NativeCULong length)
        {
            Received(session, parameter, parameterLen);
            LastInput = input.ToArray();
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
