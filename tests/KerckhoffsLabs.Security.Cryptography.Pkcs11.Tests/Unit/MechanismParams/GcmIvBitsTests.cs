using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// What <c>CK_GCM_PARAMS.ulIvBits</c> a module receives. PKCS#11 v2.40 left the field ambiguous, and NSS
/// before 3.52 reads a five-field struct without it, taking a non-zero <c>ulIvBits</c> as the AAD pointer.
/// A module bound through a v3.x interface implements the reconciled layout, and NSS 3.52 and later reject
/// the call unless <c>ulIvBits</c> is <c>ulIvLen * 8</c>. So a v3.x module gets the IV length in bits and
/// a v2.x module gets 0, as every module did before.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class GcmIvBitsTests
{
    private static readonly byte[] Aad = [0xA0, 0xA1];

    [Fact]
    public void V2Module_IsNotBoundThroughAV3Interface()
    {
        using var module = new GcmModule();
        Assert.False(module.LowLevel.IsBoundThroughV3Interface);
    }

    [Fact]
    public void V3Module_IsBoundThroughAV3Interface()
    {
        using var module = new V3GcmModule();
        Assert.True(module.LowLevel.IsBoundThroughV3Interface);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(12)]
    [InlineData(16)]
    public void V3Module_GetsTheIvLengthInBits(int ivLength)
    {
        using var module = new V3GcmModule();
        using var session = module.CreateSession();

        CK_GCM_PARAMS sent = Build(session, new byte[ivLength]);

        Assert.Equal((ulong)ivLength, (ulong)sent.IvLen);
        Assert.Equal((ulong)ivLength * 8, (ulong)sent.IvBits);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(12)]
    [InlineData(16)]
    public void V2Module_GetsZero(int ivLength)
    {
        using var module = new GcmModule();
        using var session = module.CreateSession();

        CK_GCM_PARAMS sent = Build(session, new byte[ivLength]);

        Assert.Equal((ulong)ivLength, (ulong)sent.IvLen);
        Assert.Equal(0UL, (ulong)sent.IvBits);
    }

    /// <summary>The value an encrypt call actually hands the module, through the session's own scope.</summary>
    [Theory]
    [InlineData(false, 0UL)]
    [InlineData(true, 96UL)]
    public void Encrypt_SendsTheModulesIvBits(bool v3, ulong expectedIvBits)
    {
        using GcmModule module = v3 ? new V3GcmModule() : new GcmModule();
        using var session = module.CreateSession();
        var mechanism = new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], Aad, tagBits: 128));

        Assert.ThrowsAny<Pkcs11Exception>(() => session.Encrypt(mechanism, new ObjectHandle(1), [1, 2, 3]));

        Assert.Equal(12UL, module.SentIvLen);
        Assert.Equal(expectedIvBits, module.SentIvBits);
    }

    private static CK_GCM_PARAMS Build(Pkcs11SessionCore session, byte[] iv)
    {
        using var scope = new SessionParameterScope(session);
        return new CkmAesGcmParams(iv, Aad, tagBits: 128).BuildMarshalable(scope).Read<CK_GCM_PARAMS>();
    }

    private class GcmModule : SessionTestModule
    {
        public ulong? SentIvLen { get; private set; }
        public ulong? SentIvBits { get; private set; }

        // Records the parameters and refuses the key, so the call stops before any data is processed.
        protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        {
            var p = UnmanagedMemory.Read<CK_GCM_PARAMS>(mechanism.Parameter);
            SentIvLen = (ulong)p.IvLen;
            SentIvBits = (ulong)p.IvBits;
            return CKR.CKR_KEY_HANDLE_INVALID;
        }
    }

    // Implementing a v3.0 function makes the fake hand out a v3.x interface table.
    private sealed class V3GcmModule : GcmModule
    {
        protected override CKR C_GetInterfaceList(bool listIsNull, Span<CK_INTERFACE> interfaces, ref NativeCULong count)
            => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    }
}
