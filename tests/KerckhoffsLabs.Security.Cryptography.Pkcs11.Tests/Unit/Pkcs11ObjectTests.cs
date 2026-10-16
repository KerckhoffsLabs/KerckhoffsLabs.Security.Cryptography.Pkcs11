using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="Pkcs11Object"/> against the managed token: the view's metadata, reading
/// <c>CKA_VALUE</c>, <c>Destroy</c>, and the members a disposed view must refuse. The backend
/// integration tests only cover the happy path for a certificate.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11ObjectTests
{
    private static readonly byte[] Payload = [0xDE, 0xAD, 0xBE, 0xEF];

    [Fact]
    public void FindObjects_DataObject_ExposesClassLabelIdAndValue()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        string label = NewLabel();
        ObjectHandle handle;
        using (var tpl = ObjectTemplate.ForData().Label(label).Id([0x01, 0x02]).Value(Payload).Build())
            handle = session.Core.CreateObject([.. tpl.Attributes]);

        using var objects = FindByLabel(session, label);

        var obj = Assert.Single(objects);
        Assert.Equal(handle, obj.Handle);
        Assert.Equal(CKO.CKO_DATA, obj.ObjectClass);
        Assert.Equal(label, obj.Label);
        Assert.Equal([0x01, 0x02], obj.Id.ToArray());
        Assert.Equal(Payload, obj.GetValue());
    }

    [Fact]
    public void FindObjects_ObjectWithoutLabelOrId_ReportsNullLabelAndEmptyId()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        byte[] marker = NewMarker();
        CreateBareDataObject(session, marker);

        using var objects = FindByApplication(session, marker);

        var obj = Assert.Single(objects);
        Assert.Null(obj.Label);
        Assert.True(obj.Id.IsEmpty);
    }

    /// <summary>
    /// A token that cannot hand back <c>CKA_VALUE</c> (sensitive, or not held at all) must surface
    /// as an exception, not as an empty payload a caller could mistake for real content.
    /// </summary>
    [Fact]
    public void GetValue_WhenValueIsUnreadable_ThrowsAttributeSensitive()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        byte[] marker = NewMarker();
        CreateBareDataObject(session, marker);

        using var objects = FindByApplication(session, marker);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => Assert.Single(objects).GetValue());
        Assert.Equal(CKR.CKR_ATTRIBUTE_SENSITIVE, ex.ReturnValue);
    }

    [Fact]
    public void Destroy_RemovesTheObjectFromTheToken()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        string label = NewLabel();
        using (var tpl = ObjectTemplate.ForData().Label(label).Value(Payload).Build())
            session.Core.CreateObject([.. tpl.Attributes]);

        using (var objects = FindByLabel(session, label))
            Assert.Single(objects).Destroy();

        using var after = FindByLabel(session, label);
        Assert.Empty(after);
    }

    [Fact]
    public void Destroy_WhenTheTokenRefuses_PropagatesTheReturnCode_AndLeavesTheObject()
    {
        var token = new ManagedSoftToken();
        using var library = token.Load();
        using var session = ManagedToken.OpenSession(library);
        string label = NewLabel();
        using (var tpl = ObjectTemplate.ForData().Label(label).Value(Payload).Build())
            session.Core.CreateObject([.. tpl.Attributes]);

        using (var objects = FindByLabel(session, label))
        {
            token.DestroyObjectResultOverride = CKR.CKR_ACTION_PROHIBITED;
            try
            {
                var ex = Assert.ThrowsAny<Pkcs11Exception>(() => Assert.Single(objects).Destroy());
                Assert.Equal(CKR.CKR_ACTION_PROHIBITED, ex.ReturnValue);
            }
            finally
            {
                token.DestroyObjectResultOverride = null;
            }
        }

        using var after = FindByLabel(session, label);
        Assert.Single(after);
    }

    /// <summary>
    /// Disposal is inert towards the token (see <see cref="DisposeDoesNotDestroyTests"/>), but the
    /// view itself is finished: both members that reach the session refuse to run.
    /// </summary>
    [Fact]
    public void DisposedView_RefusesGetValueAndDestroy_AndLeavesTheObject()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        string label = NewLabel();
        using (var tpl = ObjectTemplate.ForData().Label(label).Value(Payload).Build())
            session.Core.CreateObject([.. tpl.Attributes]);

        using (var objects = FindByLabel(session, label))
        {
            var obj = Assert.Single(objects);
            obj.Dispose();

            Assert.Throws<ObjectDisposedException>(() => obj.GetValue());
            Assert.Throws<ObjectDisposedException>(obj.Destroy);
            Assert.Null(Record.Exception(obj.Dispose));
        }

        using var after = FindByLabel(session, label);
        Assert.Single(after);
    }

    /// <summary>The constructor tolerates a null id so the <see cref="Pkcs11Object.Id"/> contract
    /// ("empty if unset") holds whatever the hydrating code passes.</summary>
    [Fact]
    public void Constructor_NullId_IsExposedAsEmpty()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);

        using var obj = new Pkcs11Object(session, ObjectHandle.Invalid, CKO.CKO_DATA, label: null, id: null!);

        Assert.True(obj.Id.IsEmpty);
    }

    private static string NewLabel() => $"object-{Guid.NewGuid():N}";

    private static byte[] NewMarker() => Guid.NewGuid().ToByteArray();

    // A data object with no label, id or value, tagged with CKA_APPLICATION so it can be found again.
    private static void CreateBareDataObject(Pkcs11Session session, byte[] marker)
    {
        using var tpl = ObjectTemplate.ForData().Attribute(CKA.CKA_APPLICATION, marker).Build();
        session.Core.CreateObject([.. tpl.Attributes]);
    }

    private static ReadOnlyDisposableList<Pkcs11Object> FindByLabel(Pkcs11Session session, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        return session.FindObjects(filter);
    }

    private static ReadOnlyDisposableList<Pkcs11Object> FindByApplication(Pkcs11Session session, byte[] marker)
    {
        using var filter = ObjectTemplate.Empty().Attribute(CKA.CKA_APPLICATION, marker).Build();
        return session.FindObjects(filter);
    }
}
