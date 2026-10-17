using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Objects that are neither keys nor certificates (<see cref="Pkcs11Session.OpenObject"/>,
/// <see cref="Pkcs11Session.TryOpenObject"/>, <see cref="Pkcs11Session.CreateObject"/>): the filter names the
/// class, the key lookup rules apply, and keys and certificates are left to their typed lookups.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionObjectTests : IDisposable
{
    private const string Label = "config";
    private static readonly byte[] Payload = [1, 2, 3, 4];

    private readonly Pkcs11Library _library = ManagedToken.NewLibrary();
    private readonly Pkcs11Session _session;

    public Pkcs11SessionObjectTests() => _session = ManagedToken.OpenSession(_library);

    public void Dispose()
    {
        _session.Dispose();
        _library.Dispose();
    }

    private Pkcs11Object CreateData(string label, byte[] value)
    {
        using ObjectTemplate template = ObjectTemplate.ForData().Label(label).Application("tests").Value(value).Build();
        return _session.CreateObject(template);
    }

    private static ObjectTemplate DataFilter(string label) => ObjectTemplate.ForData().Label(label).Build();

    // === Create ==============================================================

    [Fact]
    public void CreateObject_DataObject_IsStoredAndReturned()
    {
        using Pkcs11Object created = CreateData(Label, Payload);

        Assert.Equal(CKO.CKO_DATA, created.ObjectClass);
        Assert.Equal(Label, created.Label);
        Assert.Equal(Payload, created.GetValue());
    }

    [Fact]
    public void CreateObject_KeyClass_IsRefused()
    {
        using ObjectTemplate template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Value(new byte[32]).Build();

        var ex = Assert.Throws<ArgumentException>(() => _session.CreateObject(template));
        Assert.Equal("template", ex.ParamName);
    }

    [Fact]
    public void CreateObject_TemplateWithoutAClass_IsRefused()
    {
        using ObjectTemplate template = ObjectTemplate.Empty().Label(Label).Build();

        Assert.Equal("template", Assert.Throws<ArgumentException>(() => _session.CreateObject(template)).ParamName);
    }

    // === Open ================================================================

    [Fact]
    public void OpenObject_FindsTheOneDataObject()
    {
        using (CreateData(Label, Payload)) { }
        using (CreateData("other", [9])) { }

        using ObjectTemplate filter = DataFilter(Label);
        using Pkcs11Object found = _session.OpenObject(filter);

        Assert.Equal(Payload, found.GetValue());
        Assert.True(_session.TryOpenObject(filter, out Pkcs11Object? viaTry));
        using (viaTry)
            Assert.Equal(Payload, viaTry.GetValue());
    }

    // A key with the same label is another class, and the filter names the class.
    [Fact]
    public void KeySharingTheLabel_IsNotReturned()
    {
        using ObjectTemplate key = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label(Label).Value(new byte[32]).Build();
        using (_session.ImportKey(key)) { }
        using (CreateData(Label, Payload)) { }

        using ObjectTemplate filter = DataFilter(Label);
        using Pkcs11Object found = _session.OpenObject(filter);
        Assert.Equal(CKO.CKO_DATA, found.ObjectClass);
    }

    [Fact]
    public void TwoDataObjectsSharingTheLabel_AreRefused()
    {
        using (CreateData(Label, Payload)) { }
        using (CreateData(Label, [9])) { }

        using ObjectTemplate filter = DataFilter(Label);
        var ex = Assert.Throws<Pkcs11AmbiguousObjectException>(() => _session.OpenObject(filter));
        Assert.Equal(CKR.CKR_OK, ex.ReturnValue);
        Assert.Throws<Pkcs11AmbiguousObjectException>(() => _session.TryOpenObject(filter, out _));
    }

    [Fact]
    public void NoMatch_OpenThrowsNotFound_AndTryOpenReturnsFalse()
    {
        using ObjectTemplate filter = DataFilter(Label);

        var ex = Assert.Throws<Pkcs11ObjectNotFoundException>(() => _session.OpenObject(filter));
        Assert.Contains("CKO_DATA", ex.Message);
        Assert.False(_session.TryOpenObject(filter, out Pkcs11Object? none));
        Assert.Null(none);
    }

    // === Filters =============================================================

    [Fact]
    public void FilterWithoutAClass_IsRejected()
    {
        using ObjectTemplate filter = ObjectTemplate.Empty().Label(Label).Build();

        Assert.Equal("filter", Assert.Throws<ArgumentException>(() => _session.OpenObject(filter)).ParamName);
    }

    [Theory]
    [InlineData(CKO.CKO_SECRET_KEY)]
    [InlineData(CKO.CKO_PRIVATE_KEY)]
    [InlineData(CKO.CKO_PUBLIC_KEY)]
    [InlineData(CKO.CKO_CERTIFICATE)]
    public void FilterNamingAKeyOrCertificateClass_IsRejected(CKO objectClass)
    {
        using ObjectTemplate filter = ObjectTemplate.Empty().Attribute(CKA.CKA_CLASS, (ulong)objectClass).Label(Label).Build();

        Assert.Equal("filter", Assert.Throws<ArgumentException>(() => _session.TryOpenObject(filter, out _)).ParamName);
    }

    [Fact]
    public void InvalidArguments_AreRejected()
    {
        Assert.Throws<ArgumentNullException>(() => _session.OpenObject(null!));
        Assert.Throws<ArgumentNullException>(() => _session.TryOpenObject(null!, out _));
        Assert.Throws<ArgumentNullException>(() => _session.CreateObject(null!));
    }
}
