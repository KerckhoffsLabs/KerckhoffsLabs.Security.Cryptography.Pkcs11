using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Objects;

/// <summary>SoftHSM-only: create a data object, find it by label, destroy it.</summary>
internal static class ObjectLifecycleTestCases
{
    internal static void Assert_CreateFindDestroy_DataObject(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            string label = "phase-4a-test-" + Guid.NewGuid().ToString("N");
            byte[] value = Encoding.UTF8.GetBytes("phase-4a object lifecycle");

            using var attrClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
            using var attrToken = new ObjectAttribute(CKA.CKA_TOKEN, false);
            using var attrLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
            using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, value);
            var template = new List<ObjectAttribute> { attrClass, attrToken, attrLabel, attrValue };

            ObjectHandle created = session.CreateObject(template);
            try
            {
                // Find it back by label.
                using var findClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
                using var findLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
                var found = session.FindAllObjects([findClass, findLabel]);
                var obj = Assert.Single(found);

                // GetAttributeValue retrieves the value.
                using var attrs = session.GetAttributeValue(obj, [CKA.CKA_VALUE]);
                var attr = Assert.Single(attrs);
                Assert.Equal(value, attr.GetValueAsByteArray());
            }
            finally
            {
                session.DestroyObject(created);
            }

            // After destroy, the same Find returns empty.
            {
                using var verifyClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
                using var verifyLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
                var afterDestroy = session.FindAllObjects([verifyClass, verifyLabel]);
                Assert.Empty(afterDestroy);
            }
        }
        finally
        {
            TestKeys.LogoutIfRequired(backend, session);
            session.Dispose();
        }
    }
}

[Collection("SoftHsm")]
public sealed class ObjectLifecycleTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;

    [Fact(SkipUnless = nameof(SoftHsmBackendFixture.SoftHsmAvailable), SkipType = typeof(SoftHsmBackendFixture), Skip = "Requires " + nameof(SoftHsmBackendFixture.SoftHsmAvailable))]
    public void CreateFindDestroy_DataObject() => ObjectLifecycleTestCases.Assert_CreateFindDestroy_DataObject(_backend);
}
