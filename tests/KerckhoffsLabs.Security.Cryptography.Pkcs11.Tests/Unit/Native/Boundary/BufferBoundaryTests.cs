using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Boundary;

/// <summary>
/// Every <see cref="LowLevelPkcs11Library"/> wrapper that lends the module caller memory hands it exactly
/// that memory: each buffer's own address and length, nothing past either end. The buffers are
/// <see cref="GuardedMemory"/>, flush against an inaccessible page, and the module is a
/// <see cref="BoundaryProbeModule"/>, which reads or writes every byte it is told it may; so a stated length
/// one byte too long faults, and a buffer swapped for another is reported by address.
/// </summary>
/// <remarks>
/// Covered: byte inputs and outputs, a mechanism's or message's parameter block (<c>pParameter</c> and
/// <c>ulParameterLen</c>, through the Windows-packed <c>CK_MECHANISM</c> copy), the fixed 32-byte token
/// label, and the NUL-terminated async function names. Each runs at several sizes, one of them spanning a
/// page, with the guard after the buffer and before it.
/// </remarks>
[Collection(FakeModuleCollection.Name)]
public sealed class BufferBoundaryTests
{
    private static readonly NativeCULong Session = DispatchSmoke.Session;
    private static readonly NativeCULong Key = (NativeCULong)2;

    /// <summary>One wrapper call, made with buffers from <paramref name="lend"/> in argument order.</summary>
    private delegate CKR BoundaryCall(LowLevelPkcs11Library lowLevel, Lender lend);

    private static readonly Dictionary<string, BoundaryCall> Cases = new()
    {
        // Session, token and PIN management.
        ["C_InitToken"] = (l, b) => l.C_InitToken((NativeCULong)0, b.In(), b.In(32)),
        ["C_InitPIN"] = (l, b) => l.C_InitPIN(Session, b.In()),
        ["C_SetPIN"] = (l, b) => l.C_SetPIN(Session, b.In(), b.In()),
        ["C_Login"] = (l, b) => l.C_Login(Session, CKU.CKU_USER, b.In()),
        ["C_LoginUser"] = (l, b) => l.C_LoginUser(Session, CKU.CKU_USER, b.In(), b.In()),
        ["C_GetOperationState"] = (l, b) => l.C_GetOperationState(Session, b.Out(), false, out _),
        ["C_SetOperationState"] = (l, b) => l.C_SetOperationState(Session, b.In(), Key, Key),

        // Operation initialization.
        ["C_EncryptInit"] = (l, b) => { var m = b.Mechanism(); return l.C_EncryptInit(Session, ref m, Key); },
        ["C_DecryptInit"] = (l, b) => { var m = b.Mechanism(); return l.C_DecryptInit(Session, ref m, Key); },
        ["C_DigestInit"] = (l, b) => { var m = b.Mechanism(); return l.C_DigestInit(Session, ref m); },
        ["C_SignInit"] = (l, b) => { var m = b.Mechanism(); return l.C_SignInit(Session, ref m, Key); },
        ["C_SignRecoverInit"] = (l, b) => { var m = b.Mechanism(); return l.C_SignRecoverInit(Session, ref m, Key); },
        ["C_VerifyInit"] = (l, b) => { var m = b.Mechanism(); return l.C_VerifyInit(Session, ref m, Key); },
        ["C_VerifyRecoverInit"] = (l, b) => { var m = b.Mechanism(); return l.C_VerifyRecoverInit(Session, ref m, Key); },
        ["C_VerifySignatureInit"] = (l, b) => { var m = b.Mechanism(); return l.C_VerifySignatureInit(Session, ref m, Key, b.In()); },
        ["C_MessageEncryptInit"] = (l, b) => { var m = b.Mechanism(); return l.C_MessageEncryptInit(Session, ref m, Key); },
        ["C_MessageDecryptInit"] = (l, b) => { var m = b.Mechanism(); return l.C_MessageDecryptInit(Session, ref m, Key); },
        ["C_MessageSignInit"] = (l, b) => { var m = b.Mechanism(); return l.C_MessageSignInit(Session, ref m, Key); },
        ["C_MessageVerifyInit"] = (l, b) => { var m = b.Mechanism(); return l.C_MessageVerifyInit(Session, ref m, Key); },

        // Single- and multi-part operations.
        ["C_Encrypt"] = (l, b) => l.C_Encrypt(Session, b.In(), b.Out(), false, out _),
        ["C_EncryptUpdate"] = (l, b) => l.C_EncryptUpdate(Session, b.In(), b.Out(), false, out _),
        ["C_EncryptFinal"] = (l, b) => l.C_EncryptFinal(Session, b.Out(), false, out _),
        ["C_Decrypt"] = (l, b) => l.C_Decrypt(Session, b.In(), b.Out(), false, out _),
        ["C_DecryptUpdate"] = (l, b) => l.C_DecryptUpdate(Session, b.In(), b.Out(), false, out _),
        ["C_DecryptFinal"] = (l, b) => l.C_DecryptFinal(Session, b.Out(), false, out _),
        ["C_Digest"] = (l, b) => l.C_Digest(Session, b.In(), b.Out(), false, out _),
        ["C_DigestUpdate"] = (l, b) => l.C_DigestUpdate(Session, b.In()),
        ["C_DigestFinal"] = (l, b) => l.C_DigestFinal(Session, b.Out(), false, out _),
        ["C_Sign"] = (l, b) => l.C_Sign(Session, b.In(), b.Out(), false, out _),
        ["C_SignUpdate"] = (l, b) => l.C_SignUpdate(Session, b.In()),
        ["C_SignFinal"] = (l, b) => l.C_SignFinal(Session, b.Out(), false, out _),
        ["C_SignRecover"] = (l, b) => l.C_SignRecover(Session, b.In(), b.Out(), false, out _),
        ["C_Verify"] = (l, b) => l.C_Verify(Session, b.In(), b.In()),
        ["C_VerifyUpdate"] = (l, b) => l.C_VerifyUpdate(Session, b.In()),
        ["C_VerifyFinal"] = (l, b) => l.C_VerifyFinal(Session, b.In()),
        ["C_VerifyRecover"] = (l, b) => l.C_VerifyRecover(Session, b.In(), b.Out(), false, out _),
        ["C_VerifySignature"] = (l, b) => l.C_VerifySignature(Session, b.In()),
        ["C_VerifySignatureUpdate"] = (l, b) => l.C_VerifySignatureUpdate(Session, b.In()),

        // Dual-function operations.
        ["C_DigestEncryptUpdate"] = (l, b) => l.C_DigestEncryptUpdate(Session, b.In(), b.Out(), false, out _),
        ["C_DecryptDigestUpdate"] = (l, b) => l.C_DecryptDigestUpdate(Session, b.In(), b.Out(), false, out _),
        ["C_SignEncryptUpdate"] = (l, b) => l.C_SignEncryptUpdate(Session, b.In(), b.Out(), false, out _),
        ["C_DecryptVerifyUpdate"] = (l, b) => l.C_DecryptVerifyUpdate(Session, b.In(), b.Out(), false, out _),

        // Key management.
        ["C_GenerateKey"] = (l, b) => { var m = b.Mechanism(); NativeCULong k = default; return l.C_GenerateKey(Session, ref m, [], ref k); },
        ["C_GenerateKeyPair"] = (l, b) => { var m = b.Mechanism(); NativeCULong pub = default, priv = default; return l.C_GenerateKeyPair(Session, ref m, [], [], ref pub, ref priv); },
        ["C_DeriveKey"] = (l, b) => { var m = b.Mechanism(); NativeCULong k = default; return l.C_DeriveKey(Session, ref m, Key, [], ref k); },
        ["C_WrapKey"] = (l, b) => { var m = b.Mechanism(); return l.C_WrapKey(Session, ref m, Key, Key, b.Out(), false, out _); },
        ["C_UnwrapKey"] = (l, b) => { var m = b.Mechanism(); NativeCULong k = default; return l.C_UnwrapKey(Session, ref m, Key, b.In(), [], ref k); },
        ["C_EncapsulateKey"] = (l, b) => { var m = b.Mechanism(); NativeCULong k = default; return l.C_EncapsulateKey(Session, ref m, Key, [], b.Out(), false, out _, ref k); },
        ["C_DecapsulateKey"] = (l, b) => { var m = b.Mechanism(); NativeCULong k = default; return l.C_DecapsulateKey(Session, ref m, Key, [], b.In(), ref k); },
        ["C_WrapKeyAuthenticated"] = (l, b) => { var m = b.Mechanism(); return l.C_WrapKeyAuthenticated(Session, ref m, Key, Key, b.In(), b.Out(), false, out _); },
        ["C_UnwrapKeyAuthenticated"] = (l, b) => { var m = b.Mechanism(); NativeCULong k = default; return l.C_UnwrapKeyAuthenticated(Session, ref m, Key, b.In(), [], b.In(), ref k); },

        // Random numbers.
        ["C_SeedRandom"] = (l, b) => l.C_SeedRandom(Session, b.In()),
        ["C_GenerateRandom"] = (l, b) => l.C_GenerateRandom(Session, b.Out()),

        // Message-based operations.
        ["C_EncryptMessage"] = (l, b) => l.C_EncryptMessage(Session, b.Block(), b.Size, b.In(), b.In(), b.Out(), false, out _),
        ["C_EncryptMessageBegin"] = (l, b) => l.C_EncryptMessageBegin(Session, b.Block(), b.Size, b.In()),
        ["C_EncryptMessageNext"] = (l, b) => l.C_EncryptMessageNext(Session, b.Block(), b.Size, b.In(), b.Out(), false, out _, default),
        ["C_DecryptMessage"] = (l, b) => l.C_DecryptMessage(Session, b.Block(), b.Size, b.In(), b.In(), b.Out(), false, out _),
        ["C_DecryptMessageBegin"] = (l, b) => l.C_DecryptMessageBegin(Session, b.Block(), b.Size, b.In()),
        ["C_DecryptMessageNext"] = (l, b) => l.C_DecryptMessageNext(Session, b.Block(), b.Size, b.In(), b.Out(), false, out _, default),
        ["C_SignMessage"] = (l, b) => l.C_SignMessage(Session, b.Block(), b.Size, b.In(), b.Out(), false, out _),
        ["C_SignMessageBegin"] = (l, b) => l.C_SignMessageBegin(Session, b.Block(), b.Size),
        ["C_SignMessageNext"] = (l, b) => l.C_SignMessageNext(Session, b.Block(), b.Size, b.In(), b.Out(), false, out _),
        ["C_VerifyMessage"] = (l, b) => l.C_VerifyMessage(Session, b.Block(), b.Size, b.In(), b.In()),
        ["C_VerifyMessageBegin"] = (l, b) => l.C_VerifyMessageBegin(Session, b.Block(), b.Size),
        ["C_VerifyMessageNext"] = (l, b) => l.C_VerifyMessageNext(Session, b.Block(), b.Size, b.In(), b.In()),

        // Asynchronous operations.
        ["C_AsyncComplete"] = (l, b) => { CK_ASYNC_DATA result = default; return l.C_AsyncComplete(Session, b.Name("C_GenerateRandom"), ref result); },
        ["C_AsyncGetID"] = (l, b) => { NativeCULong id = default; return l.C_AsyncGetID(Session, b.Name("C_GenerateRandom"), ref id); },
        ["C_AsyncJoin"] = (l, b) => l.C_AsyncJoin(Session, b.Name("C_GenerateRandom"), (NativeCULong)1, b.In()),
    };

    public static TheoryData<string, int, GuardSide> Calls
    {
        get
        {
            var data = new TheoryData<string, int, GuardSide>();
            foreach (string function in Cases.Keys)
                foreach (int size in (int[])[1, 13, Environment.SystemPageSize + 3])
                    foreach (GuardSide side in (GuardSide[])[GuardSide.After, GuardSide.Before])
                        data.Add(function, size, side);
            return data;
        }
    }

    [Theory]
    [MemberData(nameof(Calls))]
    public void Wrapper_LendsTheModuleExactlyTheCallersBuffers(string function, int size, GuardSide side)
    {
        using var module = new BoundaryProbeModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var lend = new Lender(size, side);

        Assert.Equal(CKR.CKR_OK, Cases[function](lowLevel, lend));

        Assert.Equal(1, module.CallCount(function));
        Assert.Equal(lend.Lent, module.Received);
    }

    /// <summary>
    /// A C string reaches the module as a bare pointer, read up to its NUL. A name without one, flush against
    /// the guard page, would have the module read past the caller's memory, so the wrapper refuses it first.
    /// </summary>
    [Theory]
    [InlineData("C_AsyncComplete")]
    [InlineData("C_AsyncGetID")]
    [InlineData("C_AsyncJoin")]
    [InlineData("C_GetInterface")]
    public void NameWithoutItsNul_IsRefused_WithoutReachingTheModule(string function)
    {
        using var module = new BoundaryProbeModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        using var name = GuardedMemory.Of(function == "C_GetInterface" ? "PKCS 11"u8 : "C_GenerateRandom"u8);
        int callsBefore = module.CallCount(function); // loading the module already asked for its interface

        Assert.Throws<ArgumentException>(() =>
        {
            CK_ASYNC_DATA result = default;
            NativeCULong id = default;
            return function switch
            {
                "C_AsyncComplete" => lowLevel.C_AsyncComplete(Session, name.Span, ref result),
                "C_AsyncGetID" => lowLevel.C_AsyncGetID(Session, name.Span, ref id),
                "C_AsyncJoin" => lowLevel.C_AsyncJoin(Session, name.Span, (NativeCULong)1, []),
                _ => lowLevel.C_GetInterface(name.Span, default, out _),
            };
        });
        Assert.Equal(callsBefore, module.CallCount(function));
    }

    // Guards the table itself: a wrapper the probe implements but no case calls would go unchecked.
    [Fact]
    public void EveryFunctionTheProbeImplements_HasACase()
    {
        string[] implemented =
        [
            .. typeof(BoundaryProbeModule)
                .GetMethods(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.DeclaredOnly)
                .Where(m => m.Name.StartsWith("C_", StringComparison.Ordinal))
                .Select(m => m.Name),
        ];

        Assert.Empty(implemented.Except(Cases.Keys));
        Assert.Empty(Cases.Keys.Except(implemented));
    }

    /// <summary>
    /// Lends a call its buffers: each a fresh <see cref="GuardedMemory"/> of the test's size with the guard on
    /// the test's side, filled with a pattern, and recorded in the order lent.
    /// </summary>
    private sealed class Lender(int size, GuardSide side) : IDisposable
    {
        private readonly List<GuardedMemory> _memory = [];

        /// <summary>What was lent, as the module should see it: address and length, in argument order.</summary>
        public List<(IntPtr Address, int Length)> Lent { get; } = [];

        public NativeCULong Size => (NativeCULong)size;

        public ReadOnlySpan<byte> In() => Lend(size).Span;

        public ReadOnlySpan<byte> In(int length) => Lend(length).Span;

        public Span<byte> Out() => Lend(size).Span;

        /// <summary>A parameter block of <see cref="Size"/> bytes.</summary>
        public IntPtr Block() => Lend(size).Address;

        public CK_MECHANISM Mechanism() => new()
        {
            Mechanism = (NativeCULong)(ulong)CKM.CKM_AES_GCM,
            Parameter = Block(),
            ParameterLen = Size,
        };

        /// <summary>
        /// A NUL-terminated name. The module sees only a C string, so it is recorded by length, the NUL
        /// included, and not by address.
        /// </summary>
        public ReadOnlySpan<byte> Name(string name)
        {
            var memory = GuardedMemory.Of(Encoding.ASCII.GetBytes(name + '\0'), side);
            _memory.Add(memory);
            Lent.Add((IntPtr.Zero, memory.Length));
            return memory.Span;
        }

        private GuardedMemory Lend(int length)
        {
            var memory = GuardedMemory.Allocate(length, side);
            memory.Span.Fill(0xC3);
            _memory.Add(memory);
            Lent.Add((memory.Address, length));
            return memory;
        }

        public void Dispose()
        {
            foreach (GuardedMemory memory in _memory)
                memory.Dispose();
        }
    }
}
