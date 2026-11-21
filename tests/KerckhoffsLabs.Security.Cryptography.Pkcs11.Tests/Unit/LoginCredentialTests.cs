using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="LoginCredential"/> and the two slot methods that take one: a PIN the caller keeps, a PIN source the library
/// reads once and disposes, or the pinpad; and an optional username.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class LoginCredentialTests : IDisposable
{
    private readonly LoginTokenModule _module = new();
    private readonly Pkcs11Library _library;
    private readonly SecurePin _pin;

    public LoginCredentialTests()
    {
        _library = _module.Load();
        _pin = new SecurePin(_module.ExpectedPin);
    }

    public void Dispose()
    {
        _pin.Dispose();
        _library.Dispose();
        _module.Dispose();
    }

    private Pkcs11Slot Slot => Assert.Single(_library.GetSlotList());

    [Fact]
    public void Factories_RefuseNull()
    {
        Assert.Throws<ArgumentNullException>(() => LoginCredential.FromPin(null!));
        Assert.Throws<ArgumentNullException>(() => LoginCredential.FromPinSource(null!));
        Assert.Throws<ArgumentNullException>(() => { LoginCredential credential = (SecurePin)null!; });
    }

    [Fact]
    public void LoginAndShareOrLogin_RefuseANullCredential_AndAnEmptyUsername()
    {
        Assert.Throws<ArgumentNullException>(() => Slot.Login(TokenUser.User, (LoginCredential)null!));
        Assert.Throws<ArgumentNullException>(() => Slot.ShareOrLogin(null!));
        Assert.Throws<ArgumentException>(() => Slot.Login(TokenUser.User, _pin, ""));
        Assert.Throws<ArgumentException>(() => Slot.ShareOrLogin(_pin, ""));
        Assert.Equal(0, _module.LoginCalls);
    }

    // The common call needs no wrapping, and the caller keeps the PIN.
    [Fact]
    public void ASecurePin_ConvertsImplicitly_AndIsNotDisposed()
    {
        using (Pkcs11Login login = Slot.Login(TokenUser.User, _pin))
            Assert.True(login.IsActive);

        Assert.False(_pin.IsDisposed);
    }

    [Fact]
    public void Login_FromAPinSource_ReadsItOnce_AndDisposesThePin()
    {
        int asked = 0;
        SecurePin? given = null;

        using Pkcs11Login login = Slot.Login(TokenUser.User, LoginCredential.FromPinSource(() =>
        {
            asked++;
            return given = new SecurePin(_module.ExpectedPin);
        }));

        Assert.True(login.IsActive);
        Assert.Equal(1, asked);
        Assert.True(given!.IsDisposed);
    }

    [Fact]
    public void Login_FromAPinSourceReturningNull_IsRefused_BeforeTheModule()
    {
        Assert.Throws<InvalidOperationException>(() => Slot.Login(TokenUser.User, LoginCredential.FromPinSource(() => null!)));
        Assert.Equal(0, _module.LoginCalls);
    }

    // A refused login still disposes the PIN the source returned.
    [Fact]
    public void Login_FromAPinSource_TheTokenRefuses_ThePinIsDisposedAnyway()
    {
        SecurePin? given = null;

        Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User,
            LoginCredential.FromPinSource(() => given = new SecurePin("wrong-pin"u8))));

        Assert.True(given!.IsDisposed);
    }

    [Fact]
    public void Login_WithoutAUsername_IsTheUnnamedUser()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin, username: null);

        Assert.Null(login.Username);
    }

    [Fact]
    public void ShareOrLogin_ASecondCall_SharesTheFirstsLogin()
    {
        using Pkcs11Login first = Slot.ShareOrLogin(_pin);
        using Pkcs11Login second = Slot.ShareOrLogin(LoginCredential.FromPinSource(
            () => throw new InvalidOperationException("not asked: a login is held to share")));

        Assert.True(second.IsActive);
        Assert.Equal(1, _module.LoginCalls);
    }

    [Fact]
    public void ToString_SaysWhichKind_NeverThePin()
    {
        Assert.Equal("LoginCredential{Pin}", LoginCredential.FromPin(_pin).ToString());
        Assert.Equal("LoginCredential{PinSource}", LoginCredential.FromPinSource(() => _pin).ToString());
        Assert.Equal("LoginCredential{Pinpad}", LoginCredential.Pinpad.ToString());
    }
}
