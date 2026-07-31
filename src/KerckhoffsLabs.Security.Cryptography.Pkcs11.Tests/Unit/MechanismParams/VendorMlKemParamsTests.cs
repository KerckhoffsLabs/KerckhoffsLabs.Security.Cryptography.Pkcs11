using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// The vendor-parameter surface against opencryptoki's <c>CK_IBM_ML_KEM_PARAMS</c> — the one real
/// vendor struct available here whose packed and naturally-aligned layouts genuinely differ.
/// </summary>
/// <remarks>
/// <para>
/// From <c>usr/include/pkcs11types.h</c>:
/// </para>
/// <code>
/// typedef struct CK_IBM_ML_KEM_PARAMS {
///     CK_ULONG                ulVersion;
///     CK_IBM_ML_KEM_MODE      mode;          // CK_ULONG
///     CK_IBM_ML_KEM_KDF_TYPE  kdf;           // CK_ULONG
///     CK_BBOOL                bPrepend;      // one byte — the field that splits the layouts
///     CK_BYTE                *pCipher;
///     CK_ULONG                ulCipherLen;
///     CK_BYTE                *pSharedData;
///     CK_ULONG                ulSharedDataLen;
///     CK_OBJECT_HANDLE        hSecret;
/// } CK_IBM_ML_KEM_PARAMS;
/// </code>
/// <para>
/// <b>Why this struct earns its own test.</b> The <c>CKM_IBM_ETH_DERIVE</c> case is all word- and
/// pointer-sized fields, so packed and natural layouts coincide and it cannot tell a correct padding
/// rule from a missing one. Here the <c>CK_BBOOL</c> in the middle makes them differ by seven bytes
/// on 64-bit — 72 against 65, with <c>pCipher</c> at offset 32 rather than 25 — so this is the case
/// that would catch a writer applying the wrong platform's rule.
/// </para>
/// <para>
/// The expected sizes and offsets below are written out as constants read off the header, not
/// recomputed from the writer's own alignment logic. A test that derived them the same way the code
/// does would agree with the code by construction and prove nothing.
/// </para>
/// <para>
/// EP11 checks <c>mech->ulParameterLen != sizeof(CK_IBM_ML_KEM_PARAMS)</c> before looking at the
/// contents, so the total size is the first thing a real token would reject. Only an EP11/CEX card
/// serves this mechanism, so it cannot be exercised end to end in this repository.
/// </para>
/// </remarks>
public sealed class VendorMlKemParamsTests
{
    private const ulong CkmIbmMlKem = 0x80010037UL;   // CKM_VENDOR_DEFINED + 0x10037
    private const ulong ModeDecapsulate = 2;          // CK_IBM_ML_KEM_DECAPSULATE

    private sealed class CkmIbmMlKemParams(
        ulong version, ulong mode, ulong kdf, bool prepend,
        byte[] cipher, byte[] sharedData, ulong secretHandle)
        : VendorMechanismParameters
    {
        protected override void Describe(Pkcs11ParameterWriter writer) => writer
            .CkULong(version)
            .CkULong(mode)
            .CkULong(kdf)
            .CkBBool(prepend)
            .Buffer(cipher)
            .CkULong((ulong)cipher.Length)
            .Buffer(sharedData)
            .CkULong((ulong)sharedData.Length)
            .CkObjectHandle(secretHandle);
    }

    /// <summary>Sizes and offsets a C compiler produces for the header above, per platform.</summary>
    private static (int Total, int PrependOffset, int CipherOffset) Expected =>
        (IntPtr.Size, Pkcs11Marshal.IsWindows) switch
        {
            (8, false) => (72, 24, 32),
            (8, true) => (65, 24, 25),
            (4, false) => (36, 12, 16),
            _ => (33, 12, 13),
        };

    private static int Word => UnmanagedMemory.NativeULongSize;

    private static ulong ReadCkULong(ReadOnlySpan<byte> block, int offset) =>
        Word == 8 ? MemoryMarshal.Read<ulong>(block[offset..]) : MemoryMarshal.Read<uint>(block[offset..]);

    private static byte[] Marshal(MechanismParameters parameters, MechanismParameterScope scope)
    {
        var block = (Pkcs11ParameterBlock)parameters.BuildMarshalable(scope);
        byte[] bytes = new byte[block.Length];
        UnmanagedMemory.Read(block.Pointer, bytes);
        return bytes;
    }

    [Fact]
    public void MlKemParams_MatchTheVendorHeaderLayout()
    {
        byte[] cipher = [.. Enumerable.Range(0, 24).Select(i => (byte)(0x40 + i))];
        byte[] shared = [0x11, 0x22, 0x33];
        var parameters = new CkmIbmMlKemParams(
            version: 0, mode: ModeDecapsulate, kdf: 1, prepend: true,
            cipher, shared, secretHandle: 0x2BAD);

        using var scope = new MechanismParameterScope();
        byte[] block = Marshal(parameters, scope);

        var expected = Expected;
        Assert.Equal(expected.Total, block.Length);

        Assert.Equal(0UL, ReadCkULong(block, 0));
        Assert.Equal(ModeDecapsulate, ReadCkULong(block, Word));
        Assert.Equal(1UL, ReadCkULong(block, 2 * Word));

        // The CK_BBOOL: one byte, and the fields after it move depending on the platform's rule.
        Assert.Equal(1, block[expected.PrependOffset]);

        IntPtr pCipher = MemoryMarshal.Read<IntPtr>(block.AsSpan(expected.CipherOffset));
        Assert.NotEqual(IntPtr.Zero, pCipher);
        byte[] seenCipher = new byte[cipher.Length];
        UnmanagedMemory.Read(pCipher, seenCipher);
        Assert.Equal(cipher, seenCipher);

        int afterCipher = expected.CipherOffset + IntPtr.Size;
        Assert.Equal((ulong)cipher.Length, ReadCkULong(block, afterCipher));

        IntPtr pShared = MemoryMarshal.Read<IntPtr>(block.AsSpan(afterCipher + Word));
        byte[] seenShared = new byte[shared.Length];
        UnmanagedMemory.Read(pShared, seenShared);
        Assert.Equal(shared, seenShared);

        Assert.Equal((ulong)shared.Length, ReadCkULong(block, afterCipher + Word + IntPtr.Size));
        Assert.Equal(0x2BADUL, ReadCkULong(block, afterCipher + (2 * Word) + IntPtr.Size));
    }

    /// <summary>
    /// A false <c>CK_BBOOL</c> must still occupy its byte and still push the following pointer to the
    /// same offset — dropping the field entirely would shorten the block and a real token would
    /// reject it on the size check before ever reading a value.
    /// </summary>
    [Fact]
    public void PrependFalse_KeepsTheSameLayout()
    {
        using var scope = new MechanismParameterScope();
        byte[] block = Marshal(
            new CkmIbmMlKemParams(0, ModeDecapsulate, 1, prepend: false, [9, 9], [8], 1),
            scope);

        Assert.Equal(Expected.Total, block.Length);
        Assert.Equal(0, block[Expected.PrependOffset]);
        Assert.NotEqual(IntPtr.Zero, MemoryMarshal.Read<IntPtr>(block.AsSpan(Expected.CipherOffset)));
    }

    [Fact]
    public void MlKemParams_ReachCkMechanismUnderTheVendorType()
    {
        var mech = new Mechanism(
            CkmIbmMlKem,
            new CkmIbmMlKemParams(0, ModeDecapsulate, 1, true, [1, 2, 3], [4], 5));

        using var scope = new MechanismParameterScope();
        CK_MECHANISM marshalled = mech.Marshal(scope, out object? marshalledParams);

        Assert.Equal(CkmIbmMlKem, (ulong)marshalled.Mechanism);
        Assert.Equal((ulong)Expected.Total, (ulong)marshalled.ParameterLen);
        Assert.Null(Record.Exception(() => mech.AbsorbOutput(marshalledParams)));
    }
}
