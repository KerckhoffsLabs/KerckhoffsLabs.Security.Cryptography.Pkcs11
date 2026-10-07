using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// How <see cref="CkmPkcs5Pbkd2Params"/> holds the password: the <see cref="SecurePassword"/>
/// constructor borrows the password and keeps no copy, the span constructor keeps its own, and neither makes the
/// descriptor disposable or unshareable.
/// </summary>
public sealed class Pkcs5Pbkd2ParamsTests
{
    private static byte[] MarshalledPassword(CkmPkcs5Pbkd2Params p)
    {
        using var scope = new MechanismParameterScope();
        var s = p.BuildMarshalable(scope).Read<CK_PKCS5_PBKD2_PARAMS2>();
        int length = (int)(ulong)s.PasswordLen;
        return length == 0 ? [] : UnmanagedMemory.Read(s.Password, length);
    }

    private static CkmPkcs5Pbkd2Params Borrowing(SecurePassword password) =>
        new(new byte[16], 1000, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, password);

    [Fact]
    public void PasswordConstructor_MarshalsThePasswordBytes()
    {
        using var password = new SecurePassword("password"u8);

        Assert.Equal("password"u8.ToArray(), MarshalledPassword(Borrowing(password)));
    }

    [Fact]
    public void PasswordConstructor_AcceptsAnEmptyPassword()
    {
        using var password = new SecurePassword(ReadOnlySpan<byte>.Empty);

        Assert.Empty(MarshalledPassword(Borrowing(password)));
    }

    [Fact]
    public void PasswordConstructor_ReadsThePasswordAtMarshalTime_AndRefusesOnceItIsDisposed()
    {
        var password = new SecurePassword("password"u8);
        CkmPkcs5Pbkd2Params p = Borrowing(password);

        password.Dispose();

        Assert.Throws<ObjectDisposedException>(() => MarshalledPassword(p));
    }

    [Fact]
    public void PasswordConstructor_RejectsNull() =>
        Assert.Throws<ArgumentNullException>(() => Borrowing(null!));

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
        using var password = new SecurePassword("password"u8);
        CkmPkcs5Pbkd2Params p = Borrowing(password);

        Assert.Equal(MarshalledPassword(p), MarshalledPassword(p));
        Assert.False(typeof(IDisposable).IsAssignableFrom(typeof(CkmPkcs5Pbkd2Params)));
    }
}
