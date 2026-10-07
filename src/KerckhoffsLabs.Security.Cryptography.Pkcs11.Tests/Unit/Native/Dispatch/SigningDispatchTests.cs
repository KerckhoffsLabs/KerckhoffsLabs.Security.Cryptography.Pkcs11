using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Dispatch;

/// <summary>
/// The signing wrappers, called through a module's function table: each reaches the module with its
/// arguments, and the ones with an output follow the output rules of PKCS#11 v3.2 §5.2.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class SigningDispatchTests
{
    private static readonly byte[] Data = [0x0D, 0x0A, 0x7A];
    private static readonly byte[] Signature = [0x51, 0x52, 0x53, 0x54];

    private static readonly Dictionary<string, DispatchCase> Cases = new DispatchCase[]
    {
        new(nameof(LowLevelPkcs11Library.C_SignInit), l => { CK_MECHANISM m = Ecdsa(); return l.C_SignInit(DispatchSmoke.Session, ref m, (NativeCULong)3); }),
        new(nameof(LowLevelPkcs11Library.C_Sign), l => l.C_Sign(DispatchSmoke.Session, Data, new byte[8], lengthOnly: false, out _)),
        new(nameof(LowLevelPkcs11Library.C_SignUpdate), l => l.C_SignUpdate(DispatchSmoke.Session, Data)),
        new(nameof(LowLevelPkcs11Library.C_SignFinal), l => l.C_SignFinal(DispatchSmoke.Session, new byte[8], lengthOnly: false, out _)),
        new(nameof(LowLevelPkcs11Library.C_SignRecoverInit), l => { CK_MECHANISM m = Ecdsa(); return l.C_SignRecoverInit(DispatchSmoke.Session, ref m, (NativeCULong)3); }),
        new(nameof(LowLevelPkcs11Library.C_SignRecover), l => l.C_SignRecover(DispatchSmoke.Session, Data, new byte[8], lengthOnly: false, out _)),
    }.ToDictionary(c => c.Function, StringComparer.Ordinal);

    public static TheoryData<string> Functions => [.. Cases.Keys];

    /// <summary>The functions with an output buffer, called with the given buffer and query flag.</summary>
    private static readonly Dictionary<string, OutputCall> Outputs = new(StringComparer.Ordinal)
    {
        [nameof(LowLevelPkcs11Library.C_Sign)] = (LowLevelPkcs11Library l, Span<byte> output, bool lengthOnly, out NativeCULong length)
            => l.C_Sign(DispatchSmoke.Session, Data, output, lengthOnly, out length),
        [nameof(LowLevelPkcs11Library.C_SignFinal)] = (LowLevelPkcs11Library l, Span<byte> output, bool lengthOnly, out NativeCULong length)
            => l.C_SignFinal(DispatchSmoke.Session, output, lengthOnly, out length),
        [nameof(LowLevelPkcs11Library.C_SignRecover)] = (LowLevelPkcs11Library l, Span<byte> output, bool lengthOnly, out NativeCULong length)
            => l.C_SignRecover(DispatchSmoke.Session, Data, output, lengthOnly, out length),
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
        if (function.EndsWith("Init", StringComparison.Ordinal))
        {
            Assert.Equal((ulong)CKM.CKM_ECDSA, module.LastMechanism);
            Assert.Equal(3UL, module.LastKey);
        }
        else if (function != nameof(LowLevelPkcs11Library.C_SignFinal))
        {
            Assert.Equal(Data, module.LastInput);
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
    public void Fill_WritesTheOutput_AndReportsItsLength(string function)
    {
        using var module = new SigningModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        byte[] output = new byte[16];

        CKR rv = Outputs[function](lowLevel, output, lengthOnly: false, out NativeCULong length);

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.False(module.OutputWasNull);
        Assert.Equal(Signature, output.AsSpan(0, (int)(ulong)length).ToArray());
    }

    // An empty buffer is a real output of zero bytes, not a length query: sent as NULL, the module would
    // answer the length and leave the operation active.
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

    private static CK_MECHANISM Ecdsa() => new() { Mechanism = (NativeCULong)(ulong)CKM.CKM_ECDSA };

    /// <summary>
    /// Implements the whole signing family, records what each call received, and answers an output call
    /// the way a module does: the length for a NULL buffer, the bytes when they fit.
    /// </summary>
    private sealed class SigningModule : FakeModule
    {
        public byte[] Produces { get; init; } = Signature;
        public bool OverReports { get; init; }
        public NativeCULong? QueryReports { get; init; }

        public NativeCULong LastSession { get; private set; }
        public ulong LastMechanism { get; private set; }
        public ulong LastKey { get; private set; }
        public byte[]? LastInput { get; private set; }
        public bool OutputWasNull { get; private set; }

        protected override CKR C_SignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => Init(session, mechanism, key);
        protected override CKR C_SignRecoverInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => Init(session, mechanism, key);

        protected override CKR C_SignUpdate(NativeCULong session, ReadOnlySpan<byte> part)
        {
            LastSession = session;
            LastInput = part.ToArray();
            return CKR.CKR_OK;
        }

        protected override CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen)
            => Output(session, data, signature, ref signatureLen);

        protected override CKR C_SignFinal(NativeCULong session, NativeBuffer<byte> signature, ref NativeCULong signatureLen)
            => Output(session, default, signature, ref signatureLen);

        protected override CKR C_SignRecover(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen)
            => Output(session, data, signature, ref signatureLen);

        private CKR Init(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        {
            LastSession = session;
            LastMechanism = (ulong)mechanism.Mechanism;
            LastKey = (ulong)key;
            return CKR.CKR_OK;
        }

        private CKR Output(NativeCULong session, ReadOnlySpan<byte> input, NativeBuffer<byte> output, ref NativeCULong length)
        {
            LastSession = session;
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
