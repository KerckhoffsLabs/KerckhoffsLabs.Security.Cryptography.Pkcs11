using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Objects;

/// <summary>SoftHSM-only: create a data object, find it by label, destroy it.</summary>
internal static class ObjectLifecycleTestCases
{
    internal static void Assert_CreateFindDestroy_DataObject(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            string label = "phase-4a-test-" + Guid.NewGuid().ToString("N");
            byte[] value = System.Text.Encoding.UTF8.GetBytes("phase-4a object lifecycle");

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
                var found = session.FindAllObjects(new List<ObjectAttribute> { findClass, findLabel });
                Assert.Single(found);

                // GetAttributeValue retrieves the value.
                var attrs = session.GetAttributeValue(found[0], new List<CKA> { CKA.CKA_VALUE });
                try
                {
                    Assert.Single(attrs);
                    Assert.Equal(value, attrs[0].GetValueAsByteArray());
                }
                finally
                {
                    foreach (var a in attrs) a.Dispose();
                }
            }
            finally
            {
                session.DestroyObject(created);
            }

            // After destroy, the same Find returns empty.
            {
                using var verifyClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA);
                using var verifyLabel = new ObjectAttribute(CKA.CKA_LABEL, label);
                var afterDestroy = session.FindAllObjects(new List<ObjectAttribute> { verifyClass, verifyLabel });
                Assert.Empty(afterDestroy);
            }
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("SoftHsm")]
public sealed class ObjectLifecycleTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void CreateFindDestroy_DataObject() => ObjectLifecycleTestCases.Assert_CreateFindDestroy_DataObject(_backend);
}
