using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// A worked example of the vendor-parameter surface against a real mechanism this library does not
/// model: opencryptoki's EP11 <c>CKM_IBM_ETH_DERIVE</c> (EIP-2333 Ethereum key derivation).
/// </summary>
/// <remarks>
/// <para>
/// From <c>usr/lib/ep11_stdll/ep11.h</c>:
/// </para>
/// <code>
/// #define CKM_IBM_ETH_DERIVE   (CKM_VENDOR_DEFINED + 0x70002)
///
/// typedef struct CK_IBM_ETH_DERIVE_PARAMS {
///     CK_ULONG     version;
///     CK_ULONG     sigVersion;
///     CK_ULONG     type;            // CK_IBM_ETH_t: PRV2PRV=1, PRV2PUB=2, MASTERK=3
///     CK_ULONG     childKeyIndex;
///     CK_BYTE_PTR  pKeyInfo;
///     CK_ULONG     ulKeyInfoLen;
/// } CK_IBM_ETH_DERIVE_PARAMS;
/// </code>
/// <para>
/// The sibling tests in <c>VendorParameterWriterTests</c> pin the layout rules themselves against the
/// library's own interop structs. This file pins one concrete vendor struct end to end, because the
/// mistake it guards against is different: not a padding rule, but a field list transcribed in the
/// wrong order or with a length and its pointer swapped, which no analyzer or compiler can catch.
/// </para>
/// <para>
/// Every field here is word- or pointer-sized, so the packed and naturally-aligned layouts are
/// byte-identical on both 32- and 64-bit. That is why the offsets below can be asserted directly; a
/// struct containing a <c>CK_BBOOL</c> would differ between platforms and could not.
/// </para>
/// <para>
/// Exercising it against a token needs an IBM EP11/CEX card, so no backend in this repository's CI
/// can run it. What is verifiable here is the block the token would be handed.
/// </para>
/// </remarks>
public sealed class VendorEthDeriveParamsTests
{
    private const ulong CkmIbmEthDerive = 0x80070002UL; // CKM_VENDOR_DEFINED + 0x70002
    private const ulong Eip2333Prv2Prv = 1;             // CK_IBM_EIP2333_PRV2PRV

    /// <summary>The example a caller would write, transcribing the vendor's header field by field.</summary>
    private sealed class CkmIbmEthDeriveParams(
        ulong version, ulong sigVersion, ulong type, ulong childKeyIndex, byte[] keyInfo)
        : VendorMechanismParameters
    {
        protected override void Describe(Pkcs11ParameterWriter writer) => writer
            .CkULong(version)
            .CkULong(sigVersion)
            .CkULong(type)
            .CkULong(childKeyIndex)
            .Buffer(keyInfo)
            .CkULong((ulong)keyInfo.Length);
    }

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
    public void EthDeriveParams_MatchTheVendorHeaderLayout()
    {
        byte[] keyInfo = [.. Enumerable.Range(0, 32).Select(i => (byte)(0xA0 + i))];
        var parameters = new CkmIbmEthDeriveParams(
            version: 1, sigVersion: 2, type: Eip2333Prv2Prv, childKeyIndex: 0x1234, keyInfo);

        using var scope = new MechanismParameterScope();
        byte[] block = Marshal(parameters, scope);

        // Four CK_ULONGs, a pointer, then the length: no padding on any supported platform.
        Assert.Equal((4 * Word) + IntPtr.Size + Word, block.Length);

        Assert.Equal(1UL, ReadCkULong(block, 0));
        Assert.Equal(2UL, ReadCkULong(block, Word));
        Assert.Equal(Eip2333Prv2Prv, ReadCkULong(block, 2 * Word));
        Assert.Equal(0x1234UL, ReadCkULong(block, 3 * Word));

        // pKeyInfo must address a copy of the caller's bytes, not the bytes inline.
        IntPtr pKeyInfo = MemoryMarshal.Read<IntPtr>(block.AsSpan(4 * Word));
        Assert.NotEqual(IntPtr.Zero, pKeyInfo);
        byte[] seen = new byte[keyInfo.Length];
        UnmanagedMemory.Read(pKeyInfo, seen);
        Assert.Equal(keyInfo, seen);

        // ulKeyInfoLen follows the pointer, and describes it.
        Assert.Equal((ulong)keyInfo.Length, ReadCkULong(block, (4 * Word) + IntPtr.Size));
    }

    /// <summary>
    /// The assertions above have to be sensitive to field order, or they would pass for any struct of
    /// the same size — which is the failure mode a hand-transcribed field list actually has.
    /// </summary>
    [Fact]
    public void SwappingTwoFields_ChangesTheBlock()
    {
        byte[] keyInfo = [1, 2, 3, 4];
        using var scope = new MechanismParameterScope();

        byte[] correct = Marshal(
            new CkmIbmEthDeriveParams(version: 1, sigVersion: 2, type: 3, childKeyIndex: 4, keyInfo),
            scope);
        byte[] swapped = Marshal(
            new CkmIbmEthDeriveParams(version: 2, sigVersion: 1, type: 3, childKeyIndex: 4, keyInfo),
            scope);

        Assert.Equal(correct.Length, swapped.Length);
        Assert.NotEqual(correct, swapped);
    }

    /// <summary>
    /// An absent key-info blob is a NULL pointer with a zero length, not a pointer to nothing — the
    /// distinction PKCS#11 modules test for.
    /// </summary>
    [Fact]
    public void EmptyKeyInfo_IsNullPointerAndZeroLength()
    {
        using var scope = new MechanismParameterScope();
        byte[] block = Marshal(
            new CkmIbmEthDeriveParams(version: 1, sigVersion: 1, type: Eip2333Prv2Prv, childKeyIndex: 0, []),
            scope);

        Assert.Equal(IntPtr.Zero, MemoryMarshal.Read<IntPtr>(block.AsSpan(4 * Word)));
        Assert.Equal(0UL, ReadCkULong(block, (4 * Word) + IntPtr.Size));
    }

    /// <summary>The whole point: this reaches a mechanism the library has no enum value for.</summary>
    [Fact]
    public void EthDeriveParams_ReachCkMechanismUnderTheVendorType()
    {
        byte[] keyInfo = [0xEE, 0xFF];
        var mech = new Mechanism(
            CkmIbmEthDerive,
            new CkmIbmEthDeriveParams(version: 1, sigVersion: 1, type: Eip2333Prv2Prv, childKeyIndex: 7, keyInfo));

        using var scope = new MechanismParameterScope();
        CK_MECHANISM marshalled = mech.Marshal(scope, out object? marshalledParams);

        Assert.Equal(CkmIbmEthDerive, (ulong)marshalled.Mechanism);
        Assert.NotEqual(IntPtr.Zero, marshalled.Parameter);
        Assert.Equal((ulong)((4 * Word) + IntPtr.Size + Word), (ulong)marshalled.ParameterLen);

        // A derive parameter block carries no token output, so absorbing is a no-op rather than a throw.
        Assert.Null(Record.Exception(() => mech.AbsorbOutput(marshalledParams)));
    }
}
