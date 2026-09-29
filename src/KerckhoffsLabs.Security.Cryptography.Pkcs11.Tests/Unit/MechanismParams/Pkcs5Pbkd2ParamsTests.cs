using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// How <see cref="CkmPkcs5Pbkd2Params"/> holds the password: the <see cref="SecurePin"/> constructor
/// borrows the pin and keeps no copy, the span constructor keeps its own, and neither makes the
/// descriptor disposable or unshareable.
/// </summary>
public sealed class Pkcs5Pbkd2ParamsTests
{
    private static byte[] MarshalledPassword(CkmPkcs5Pbkd2Params p)
    {
        using var scope = new MechanismParameterScope();
        var s = (CK_PKCS5_PBKD2_PARAMS2)p.BuildMarshalable(scope);
        int length = (int)(ulong)s.PasswordLen;
        return length == 0 ? [] : UnmanagedMemory.Read(s.Password, length);
    }

    private static CkmPkcs5Pbkd2Params WithPin(SecurePin pin) =>
        new(new byte[16], 1000, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, pin);

    [Fact]
    public void PinConstructor_MarshalsThePinsBytes()
    {
        using var pin = new SecurePin("password"u8);

        Assert.Equal("password"u8.ToArray(), MarshalledPassword(WithPin(pin)));
    }

    [Fact]
    public void PinConstructor_ReadsThePinAtMarshalTime_AndRefusesOnceItIsDisposed()
    {
        var pin = new SecurePin("password"u8);
        CkmPkcs5Pbkd2Params p = WithPin(pin);

        pin.Dispose();

        Assert.Throws<ObjectDisposedException>(() => MarshalledPassword(p));
    }

    [Fact]
    public void PinConstructor_RejectsNull() =>
        Assert.Throws<ArgumentNullException>(() => WithPin(null!));

    [Fact]
    public void SpanConstructor_KeepsItsOwnCopy()
    {
        byte[] password = "password"u8.ToArray();
        var p = new CkmPkcs5Pbkd2Params(new byte[16], 1000, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, password);

        password.AsSpan().Clear();

        Assert.Equal("password"u8.ToArray(), MarshalledPassword(p));
    }

    [Fact]
    public void SpanConstructor_AcceptsAnEmptyPassword() =>
        Assert.Empty(MarshalledPassword(new CkmPkcs5Pbkd2Params(new byte[16], 1000, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, default(ReadOnlySpan<byte>))));

    [Fact]
    public void Descriptor_IsShareableAcrossCalls_AndNotDisposable()
    {
        using var pin = new SecurePin("password"u8);
        CkmPkcs5Pbkd2Params p = WithPin(pin);

        Assert.Equal(MarshalledPassword(p), MarshalledPassword(p));
        Assert.False(typeof(IDisposable).IsAssignableFrom(typeof(CkmPkcs5Pbkd2Params)));
    }
}
