using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Dispatch;

/// <summary>
/// The verification wrappers, the v3.2 signature-only ones included, called through a module's function
/// table: each reaches the module with its arguments, and <c>C_VerifyRecover</c> follows the output rules
/// of PKCS#11 v3.2 §5.2.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class VerifyingDispatchTests
{
    private static readonly byte[] Data = [0x0D, 0x0A, 0x7A];
    private static readonly byte[] Signature = [0x51, 0x52, 0x53, 0x54];
    private static readonly byte[] Recovered = [0x61, 0x62];

    private static readonly Dictionary<string, DispatchCase> Cases = new DispatchCase[]
    {
        new(nameof(LowLevelPkcs11Library.C_VerifyInit), l => { CK_MECHANISM m = Ecdsa(); return l.C_VerifyInit(DispatchSmoke.Session, ref m, (NativeCULong)3); }),
        new(nameof(LowLevelPkcs11Library.C_Verify), l => l.C_Verify(DispatchSmoke.Session, Data, Signature)),
        new(nameof(LowLevelPkcs11Library.C_VerifyUpdate), l => l.C_VerifyUpdate(DispatchSmoke.Session, Data)),
        new(nameof(LowLevelPkcs11Library.C_VerifyFinal), l => l.C_VerifyFinal(DispatchSmoke.Session, Signature)),
        new(nameof(LowLevelPkcs11Library.C_VerifyRecoverInit), l => { CK_MECHANISM m = Ecdsa(); return l.C_VerifyRecoverInit(DispatchSmoke.Session, ref m, (NativeCULong)3); }),
        new(nameof(LowLevelPkcs11Library.C_VerifyRecover), l => l.C_VerifyRecover(DispatchSmoke.Session, Signature, new byte[8], lengthOnly: false, out _)),
        new(nameof(LowLevelPkcs11Library.C_VerifySignatureInit), l => { CK_MECHANISM m = Ecdsa(); return l.C_VerifySignatureInit(DispatchSmoke.Session, ref m, (NativeCULong)3, Signature); }),
        new(nameof(LowLevelPkcs11Library.C_VerifySignature), l => l.C_VerifySignature(DispatchSmoke.Session, Data)),
        new(nameof(LowLevelPkcs11Library.C_VerifySignatureUpdate), l => l.C_VerifySignatureUpdate(DispatchSmoke.Session, Data)),
        new(nameof(LowLevelPkcs11Library.C_VerifySignatureFinal), l => l.C_VerifySignatureFinal(DispatchSmoke.Session)),
    }.ToDictionary(c => c.Function, StringComparer.Ordinal);

    public static TheoryData<string> Functions => [.. Cases.Keys];

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_ReachesTheModule_WithItsArguments(string function)
    {
        using var module = new VerifyingModule();

        Assert.Equal(CKR.CKR_OK, DispatchSmoke.ReachesTheModule(module, Cases[function]));

        Assert.Equal((ulong)DispatchSmoke.Session, (ulong)module.LastSession);
        if (function.EndsWith("Init", StringComparison.Ordinal))
        {
            Assert.Equal((ulong)CKM.CKM_ECDSA, module.LastMechanism);
            Assert.Equal(3UL, module.LastKey);
        }
        if (function is nameof(LowLevelPkcs11Library.C_Verify) or nameof(LowLevelPkcs11Library.C_VerifyUpdate)
            or nameof(LowLevelPkcs11Library.C_VerifySignature) or nameof(LowLevelPkcs11Library.C_VerifySignatureUpdate))
        {
            Assert.Equal(Data, module.LastData);
        }
        if (function is nameof(LowLevelPkcs11Library.C_Verify) or nameof(LowLevelPkcs11Library.C_VerifyFinal)
            or nameof(LowLevelPkcs11Library.C_VerifyRecover) or nameof(LowLevelPkcs11Library.C_VerifySignatureInit))
        {
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
    public void VerifyRecover_LengthQuery_SendsNoBuffer_AndReturnsTheLength()
    {
        using var module = new VerifyingModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        CKR rv = lowLevel.C_VerifyRecover(DispatchSmoke.Session, Signature, new byte[16], lengthOnly: true, out NativeCULong length);

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.True(module.OutputWasNull);
        Assert.Equal((ulong)Recovered.Length, (ulong)length);
    }

    [Fact]
    public void VerifyRecover_Fill_WritesTheRecoveredData()
    {
        using var module = new VerifyingModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        byte[] output = new byte[16];

        CKR rv = lowLevel.C_VerifyRecover(DispatchSmoke.Session, Signature, output, lengthOnly: false, out NativeCULong length);

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.False(module.OutputWasNull);
        Assert.Equal(Recovered, output.AsSpan(0, (int)(ulong)length).ToArray());
    }

    [Fact]
    public void VerifyRecover_FillIntoAnEmptyBuffer_IsNotALengthQuery()
    {
        using var module = new VerifyingModule { Recovers = [] };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        CKR rv = lowLevel.C_VerifyRecover(DispatchSmoke.Session, Signature, [], lengthOnly: false, out NativeCULong length);

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.False(module.OutputWasNull);
        Assert.Equal(0UL, (ulong)length);
    }

    [Fact]
    public void VerifyRecover_FillReportingMoreThanTheBuffer_IsRefused()
    {
        using var module = new VerifyingModule { OverReports = true };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Throws<Pkcs11UnclassifiedException>(() => lowLevel.C_VerifyRecover(DispatchSmoke.Session, Signature, new byte[16], lengthOnly: false, out _));
    }

    [Fact]
    public void VerifyRecover_LengthQueryReportingUnavailableInformation_IsRefused()
    {
        using var module = new VerifyingModule { QueryReports = NativeCULong.MaxValue };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Throws<Pkcs11UnclassifiedException>(() => lowLevel.C_VerifyRecover(DispatchSmoke.Session, Signature, default, lengthOnly: true, out _));
    }

    private static CK_MECHANISM Ecdsa() => new() { Mechanism = (NativeCULong)(ulong)CKM.CKM_ECDSA };

    /// <summary>Implements the whole verification family and records what each call received.</summary>
    private sealed class VerifyingModule : FakeModule
    {
        public byte[] Recovers { get; init; } = Recovered;
        public bool OverReports { get; init; }
        public NativeCULong? QueryReports { get; init; }

        public NativeCULong LastSession { get; private set; }
        public ulong LastMechanism { get; private set; }
        public ulong LastKey { get; private set; }
        public byte[]? LastData { get; private set; }
        public byte[]? LastSignature { get; private set; }
        public bool OutputWasNull { get; private set; }

        protected override CKR C_VerifyInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => Init(session, mechanism, key);
        protected override CKR C_VerifyRecoverInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => Init(session, mechanism, key);

        protected override CKR C_VerifySignatureInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key, ReadOnlySpan<byte> signature)
        {
            LastSignature = signature.ToArray();
            return Init(session, mechanism, key);
        }

        protected override CKR C_Verify(NativeCULong session, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            LastSignature = signature.ToArray();
            return Input(session, data);
        }

        protected override CKR C_VerifyUpdate(NativeCULong session, ReadOnlySpan<byte> part) => Input(session, part);
        protected override CKR C_VerifySignature(NativeCULong session, ReadOnlySpan<byte> data) => Input(session, data);
        protected override CKR C_VerifySignatureUpdate(NativeCULong session, ReadOnlySpan<byte> part) => Input(session, part);

        protected override CKR C_VerifyFinal(NativeCULong session, ReadOnlySpan<byte> signature)
        {
            LastSession = session;
            LastSignature = signature.ToArray();
            return CKR.CKR_OK;
        }

        protected override CKR C_VerifySignatureFinal(NativeCULong session)
        {
            LastSession = session;
            return CKR.CKR_OK;
        }

        protected override CKR C_VerifyRecover(NativeCULong session, ReadOnlySpan<byte> signature, NativeBuffer<byte> data, ref NativeCULong dataLen)
        {
            LastSession = session;
            LastSignature = signature.ToArray();
            OutputWasNull = data.IsNull;
            if (data.IsNull)
            {
                dataLen = QueryReports ?? (NativeCULong)(ulong)Recovers.Length;
                return CKR.CKR_OK;
            }
            if (data.Span.Length < Recovers.Length)
            {
                dataLen = (NativeCULong)(ulong)Recovers.Length;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }
            Recovers.CopyTo(data.Span);
            dataLen = (NativeCULong)(ulong)(OverReports ? data.Span.Length + 1 : Recovers.Length);
            return CKR.CKR_OK;
        }

        private CKR Init(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        {
            LastSession = session;
            LastMechanism = (ulong)mechanism.Mechanism;
            LastKey = (ulong)key;
            return CKR.CKR_OK;
        }

        private CKR Input(NativeCULong session, ReadOnlySpan<byte> data)
        {
            LastSession = session;
            LastData = data.ToArray();
            return CKR.CKR_OK;
        }
    }
}
