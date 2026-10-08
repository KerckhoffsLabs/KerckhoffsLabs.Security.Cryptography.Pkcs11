using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Dispatch;

/// <summary>
/// The key-management wrappers, the v3.2 encapsulation and authenticated-wrap ones included, called through
/// a module's function table: each reaches the module with its mechanism, keys and templates (in the
/// Pack=1 layout on Windows), writes the handles the module returns back to the caller, and the ones with
/// an output follow the output rules of PKCS#11 v3.2 §5.2.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class KeyManagementDispatchTests
{
    private static readonly byte[] Input = [0x0D, 0x0A, 0x7A];
    private static readonly byte[] Produced = [0x51, 0x52, 0x53, 0x54];
    private static readonly CK_ATTRIBUTE[] Template =
    [
        new() { type = (NativeCULong)(ulong)CKA.CKA_TOKEN },
        new() { type = (NativeCULong)(ulong)CKA.CKA_LABEL },
    ];
    private static readonly ulong[] TemplateTypes = [(ulong)CKA.CKA_TOKEN, (ulong)CKA.CKA_LABEL];
    private const ulong NewKey = 0x51;

    private static readonly Dictionary<string, DispatchCase> Cases = new DispatchCase[]
    {
        new(nameof(LowLevelPkcs11Library.C_GenerateKey), l =>
        {
            CK_MECHANISM m = Mechanism(); NativeCULong key = default;
            CKR rv = l.C_GenerateKey(DispatchSmoke.Session, ref m, Template, ref key);
            return Returned(rv, key);
        }),
        new(nameof(LowLevelPkcs11Library.C_GenerateKeyPair), l =>
        {
            CK_MECHANISM m = Mechanism(); NativeCULong pub = default, priv = default;
            CKR rv = l.C_GenerateKeyPair(DispatchSmoke.Session, ref m, Template, Template, ref pub, ref priv);
            return (ulong)priv == NewKey + 1 ? Returned(rv, pub) : Returned(rv, default);
        }),
        new(nameof(LowLevelPkcs11Library.C_WrapKey), l =>
        {
            CK_MECHANISM m = Mechanism();
            return l.C_WrapKey(DispatchSmoke.Session, ref m, (NativeCULong)3, (NativeCULong)4, new byte[8], lengthOnly: false, out _);
        }),
        new(nameof(LowLevelPkcs11Library.C_UnwrapKey), l =>
        {
            CK_MECHANISM m = Mechanism(); NativeCULong key = default;
            CKR rv = l.C_UnwrapKey(DispatchSmoke.Session, ref m, (NativeCULong)3, Input, Template, ref key);
            return Returned(rv, key);
        }),
        new(nameof(LowLevelPkcs11Library.C_DeriveKey), l =>
        {
            CK_MECHANISM m = Mechanism(); NativeCULong key = default;
            CKR rv = l.C_DeriveKey(DispatchSmoke.Session, ref m, (NativeCULong)3, Template, ref key);
            return Returned(rv, key);
        }),
        new(nameof(LowLevelPkcs11Library.C_EncapsulateKey), l =>
        {
            CK_MECHANISM m = Mechanism(); NativeCULong key = default;
            CKR rv = l.C_EncapsulateKey(DispatchSmoke.Session, ref m, (NativeCULong)3, Template, new byte[8], lengthOnly: false, out _, ref key);
            return Returned(rv, key);
        }),
        new(nameof(LowLevelPkcs11Library.C_DecapsulateKey), l =>
        {
            CK_MECHANISM m = Mechanism(); NativeCULong key = default;
            CKR rv = l.C_DecapsulateKey(DispatchSmoke.Session, ref m, (NativeCULong)3, Template, Input, ref key);
            return Returned(rv, key);
        }),
        new(nameof(LowLevelPkcs11Library.C_WrapKeyAuthenticated), l =>
        {
            CK_MECHANISM m = Mechanism();
            return l.C_WrapKeyAuthenticated(DispatchSmoke.Session, ref m, (NativeCULong)3, (NativeCULong)4, Input, new byte[8], lengthOnly: false, out _);
        }),
        new(nameof(LowLevelPkcs11Library.C_UnwrapKeyAuthenticated), l =>
        {
            CK_MECHANISM m = Mechanism(); NativeCULong key = default;
            CKR rv = l.C_UnwrapKeyAuthenticated(DispatchSmoke.Session, ref m, (NativeCULong)3, Input, Template, Input, ref key);
            return Returned(rv, key);
        }),
    }.ToDictionary(c => c.Function, StringComparer.Ordinal);

    public static TheoryData<string> Functions => [.. Cases.Keys];

    private static readonly HashSet<string> TakesTemplate =
    [
        nameof(LowLevelPkcs11Library.C_GenerateKey), nameof(LowLevelPkcs11Library.C_GenerateKeyPair), nameof(LowLevelPkcs11Library.C_UnwrapKey),
        nameof(LowLevelPkcs11Library.C_DeriveKey), nameof(LowLevelPkcs11Library.C_EncapsulateKey), nameof(LowLevelPkcs11Library.C_DecapsulateKey),
        nameof(LowLevelPkcs11Library.C_UnwrapKeyAuthenticated),
    ];

    private static readonly HashSet<string> TakesInput =
    [
        nameof(LowLevelPkcs11Library.C_UnwrapKey), nameof(LowLevelPkcs11Library.C_DecapsulateKey),
        nameof(LowLevelPkcs11Library.C_WrapKeyAuthenticated), nameof(LowLevelPkcs11Library.C_UnwrapKeyAuthenticated),
    ];

    /// <summary>The functions with an output buffer, called with the given buffer and query flag.</summary>
    private static readonly Dictionary<string, OutputCall> Outputs = new(StringComparer.Ordinal)
    {
        [nameof(LowLevelPkcs11Library.C_WrapKey)] = (LowLevelPkcs11Library l, Span<byte> output, bool lengthOnly, out NativeCULong length) =>
        {
            CK_MECHANISM m = Mechanism();
            return l.C_WrapKey(DispatchSmoke.Session, ref m, (NativeCULong)3, (NativeCULong)4, output, lengthOnly, out length);
        },
        [nameof(LowLevelPkcs11Library.C_EncapsulateKey)] = (LowLevelPkcs11Library l, Span<byte> output, bool lengthOnly, out NativeCULong length) =>
        {
            CK_MECHANISM m = Mechanism(); NativeCULong key = default;
            return l.C_EncapsulateKey(DispatchSmoke.Session, ref m, (NativeCULong)3, Template, output, lengthOnly, out length, ref key);
        },
        [nameof(LowLevelPkcs11Library.C_WrapKeyAuthenticated)] = (LowLevelPkcs11Library l, Span<byte> output, bool lengthOnly, out NativeCULong length) =>
        {
            CK_MECHANISM m = Mechanism();
            return l.C_WrapKeyAuthenticated(DispatchSmoke.Session, ref m, (NativeCULong)3, (NativeCULong)4, Input, output, lengthOnly, out length);
        },
    };

    public static TheoryData<string> OutputFunctions => [.. Outputs.Keys];

    private delegate CKR OutputCall(LowLevelPkcs11Library lowLevel, Span<byte> output, bool lengthOnly, out NativeCULong length);

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_ReachesTheModule_WithItsArguments_AndReturnsTheHandles(string function)
    {
        using var module = new KeyModule();

        Assert.Equal(CKR.CKR_OK, DispatchSmoke.ReachesTheModule(module, Cases[function]));

        Assert.Equal((ulong)DispatchSmoke.Session, (ulong)module.LastSession);
        Assert.Equal((ulong)CKM.CKM_AES_KEY_WRAP_KWP, module.LastMechanism);
        if (TakesTemplate.Contains(function))
            Assert.Equal(TemplateTypes, module.LastTemplate);
        if (TakesInput.Contains(function))
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
        using var module = new KeyModule();
        DispatchSmoke.RefusesACallAfterDispose(module, Cases[function]);
    }

    [Theory]
    [MemberData(nameof(OutputFunctions))]
    public void LengthQuery_SendsNoBuffer_AndReturnsTheLength(string function)
    {
        using var module = new KeyModule();
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
        using var module = new KeyModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        byte[] output = new byte[16];

        CKR rv = Outputs[function](lowLevel, output, lengthOnly: false, out NativeCULong length);

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.False(module.OutputWasNull);
        Assert.Equal(Produced, output.AsSpan(0, (int)(ulong)length).ToArray());
    }

    [Theory]
    [MemberData(nameof(OutputFunctions))]
    public void Fill_IntoAnEmptyBuffer_IsNotALengthQuery(string function)
    {
        using var module = new KeyModule { Produces = [] };
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
        using var module = new KeyModule { OverReports = true };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Throws<Pkcs11UnclassifiedException>(() => Outputs[function](lowLevel, new byte[16], lengthOnly: false, out _));
    }

    [Theory]
    [MemberData(nameof(OutputFunctions))]
    public void LengthQuery_ReportingUnavailableInformation_IsRefused(string function)
    {
        using var module = new KeyModule { QueryReports = NativeCULong.MaxValue };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Throws<Pkcs11UnclassifiedException>(() => Outputs[function](lowLevel, default, lengthOnly: true, out _));
    }

    private static CK_MECHANISM Mechanism() => new() { Mechanism = (NativeCULong)(ulong)CKM.CKM_AES_KEY_WRAP_KWP };

    // A handle-returning call succeeds only if the module's new handle came back; CKR_GENERAL_ERROR otherwise.
    private static CKR Returned(CKR rv, NativeCULong key) => rv == CKR.CKR_OK && (ulong)key != NewKey ? CKR.CKR_GENERAL_ERROR : rv;

    /// <summary>
    /// Implements the whole key-management family, records what each call received, hands out
    /// <see cref="NewKey"/> (and the next handle for a key pair's private half), and answers an output call
    /// the way a module does.
    /// </summary>
    private sealed class KeyModule : FakeModule
    {
        public byte[] Produces { get; init; } = Produced;
        public bool OverReports { get; init; }
        public NativeCULong? QueryReports { get; init; }

        public NativeCULong LastSession { get; private set; }
        public ulong LastMechanism { get; private set; }
        public ulong[]? LastTemplate { get; private set; }
        public byte[]? LastInput { get; private set; }
        public bool OutputWasNull { get; private set; }

        protected override CKR C_GenerateKey(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, ref NativeCULong key)
            => Created(session, mechanism, template, default, ref key);

        protected override CKR C_GenerateKeyPair(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicKeyTemplate,
            CK_ATTRIBUTE[] privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey)
        {
            privateKey = (NativeCULong)(NewKey + 1);
            return Created(session, mechanism, privateKeyTemplate, default, ref publicKey);
        }

        protected override CKR C_UnwrapKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey,
            CK_ATTRIBUTE[] template, ref NativeCULong key)
            => Created(session, mechanism, template, wrappedKey, ref key);

        protected override CKR C_DeriveKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[] template, ref NativeCULong key)
            => Created(session, mechanism, template, default, ref key);

        protected override CKR C_DecapsulateKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong privateKey, CK_ATTRIBUTE[] template,
            ReadOnlySpan<byte> ciphertext, ref NativeCULong key)
            => Created(session, mechanism, template, ciphertext, ref key);

        protected override CKR C_UnwrapKeyAuthenticated(NativeCULong session, CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey,
            CK_ATTRIBUTE[] template, ReadOnlySpan<byte> associatedData, ref NativeCULong key)
            => Created(session, mechanism, template, associatedData, ref key);

        protected override CKR C_WrapKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key,
            NativeBuffer<byte> wrappedKey, ref NativeCULong wrappedKeyLen)
            => Output(session, mechanism, default, wrappedKey, ref wrappedKeyLen);

        protected override CKR C_EncapsulateKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong publicKey, CK_ATTRIBUTE[] template,
            NativeBuffer<byte> ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong key)
        {
            LastTemplate = Types(template);
            key = (NativeCULong)NewKey;
            return Output(session, mechanism, default, ciphertext, ref ciphertextLen);
        }

        protected override CKR C_WrapKeyAuthenticated(NativeCULong session, CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key,
            ReadOnlySpan<byte> associatedData, NativeBuffer<byte> wrappedKey, ref NativeCULong wrappedKeyLen)
            => Output(session, mechanism, associatedData, wrappedKey, ref wrappedKeyLen);

        private CKR Created(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, ReadOnlySpan<byte> input, ref NativeCULong key)
        {
            Received(session, mechanism, input);
            LastTemplate = Types(template);
            key = (NativeCULong)NewKey;
            return CKR.CKR_OK;
        }

        private void Received(NativeCULong session, CK_MECHANISM mechanism, ReadOnlySpan<byte> input)
        {
            LastSession = session;
            LastMechanism = (ulong)mechanism.Mechanism;
            LastInput = input.ToArray();
        }

        private CKR Output(NativeCULong session, CK_MECHANISM mechanism, ReadOnlySpan<byte> input, NativeBuffer<byte> output, ref NativeCULong length)
        {
            Received(session, mechanism, input);
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

        private static ulong[] Types(CK_ATTRIBUTE[] template) => [.. template.Select(a => (ulong)a.type)];
    }
}
