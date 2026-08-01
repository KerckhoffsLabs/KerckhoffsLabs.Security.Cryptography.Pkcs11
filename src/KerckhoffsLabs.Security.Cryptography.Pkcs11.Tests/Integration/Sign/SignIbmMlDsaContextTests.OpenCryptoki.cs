using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Sign;

/// <summary>
/// Drives a vendor mechanism against a real token: opencryptoki's <c>CKM_IBM_ML_DSA</c> with a
/// <c>CK_IBM_SIGN_ADDITIONAL_CONTEXT</c> parameter built by <see cref="Pkcs11ParameterWriter"/>.
/// </summary>
/// <remarks>
/// <para>
/// Every other test of the vendor-parameter surface checks our bytes against our own understanding of
/// the layout. This one checks them against <b>a module that will reject them if they are wrong</b>:
/// <c>common/mech_pqc.c</c> validates <c>len != sizeof(CK_IBM_SIGN_ADDITIONAL_CONTEXT)</c> and returns
/// <c>CKR_MECHANISM_PARAM_INVALID</c>, so a block of the wrong size cannot pass silently.
/// </para>
/// <code>
/// typedef struct CK_IBM_SIGN_ADDITIONAL_CONTEXT {
///     CK_IBM_HEDGE_TYPE hedgeVariant;   // CK_ULONG
///     CK_BYTE_PTR       pContext;
///     CK_ULONG          ulContextLen;
/// } CK_IBM_SIGN_ADDITIONAL_CONTEXT;
/// </code>
/// <para>
/// The parameter is optional for this mechanism — passing none is legal — which is why supplying one
/// and having the token accept it is the interesting case.
/// </para>
/// <para>
/// Runs only on the ubuntu-latest CI leg, which builds the vendored opencryptoki against OpenSSL 3.5;
/// it skips everywhere else, including locally. Skips rather than fails if the token declines the
/// mechanism/key-type combination altogether, because that says nothing about our layout — but a
/// <c>CKR_MECHANISM_PARAM_INVALID</c> is treated as a real failure, since that is precisely the
/// verdict this test exists to collect.
/// </para>
/// </remarks>
[Collection("OpenCryptoki")]
public sealed class SignIbmMlDsaContextTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private const ulong CkmIbmMlDsa = 0x80010036UL;  // CKM_VENDOR_DEFINED + 0x10036
    private const ulong HedgePreferred = 0;          // CK_IBM_HEDGE_PREFERRED

    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    /// <summary>The caller-authored descriptor, transcribed from the vendor header.</summary>
    private sealed class CkIbmSignAdditionalContext(ulong hedgeVariant, byte[] context)
        : VendorMechanismParameters
    {
        protected override void Describe(Pkcs11ParameterWriter writer) => writer
            .CkULong(hedgeVariant)
            .Buffer(context)
            .CkULong((ulong)context.Length);
    }

    private void RequireIbmMlDsa()
    {
        if (!_backend.Supports(CKM.CKM_ML_DSA_KEY_PAIR_GEN))
            throw new SkipTestException("opencryptoki: CKM_ML_DSA_KEY_PAIR_GEN not available (needs OpenSSL 3.5).");
        if (!_backend.Supports((CKM)CkmIbmMlDsa))
            throw new SkipTestException("opencryptoki: CKM_IBM_ML_DSA not advertised by this token.");
    }

    [ConditionalFact(nameof(Available))]
    public void IbmMlDsa_WithSignAdditionalContext_TokenAcceptsTheParameterBlock()
    {
        RequireIbmMlDsa();

        // OpenWorkspace is a default interface method, so it is reached through IPkcs11Backend.
        using var workspace = ((IPkcs11Backend)_backend).OpenWorkspace();
        string label = $"ibm-mldsa-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_ML_DSA)
            .Label(label).Id(id).Verify()
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlDsa.CKP_ML_DSA_65).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_DSA)
            .Label(label).Id(id).Sign().Build();

        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_ML_DSA_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            byte[] data = Encoding.UTF8.GetBytes("vendor parameter block, built by the library");
            byte[] context = [0xC0, 0x17, 0xEC, 0x71];

            var mech = new Mechanism(CkmIbmMlDsa, new CkIbmSignAdditionalContext(HedgePreferred, context));

            byte[] signature;
            try
            {
                signature = key.Sign(mech, data);
            }
            catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_MECHANISM_PARAM_INVALID)
            {
                // The one outcome that indicts our marshalling rather than the token's capabilities.
                throw new Xunit.Sdk.XunitException(
                    "opencryptoki rejected the CK_IBM_SIGN_ADDITIONAL_CONTEXT block as malformed "
                    + $"(CKR_MECHANISM_PARAM_INVALID). Expected length {(3 * IntPtr.Size)} bytes on this platform.");
            }
            catch (Pkcs11Exception ex)
            {
                throw new SkipTestException(
                    $"opencryptoki will not run CKM_IBM_ML_DSA against a CKK_ML_DSA key here ({ex.ReturnValue}); "
                    + "nothing to conclude about the parameter block.");
            }

            Assert.NotEmpty(signature);

            // The same descriptor must drive verification, which also proves it is reusable.
            var verifyMech = new Mechanism(CkmIbmMlDsa, new CkIbmSignAdditionalContext(HedgePreferred, context));
            Assert.True(key.Verify(verifyMech, data, signature));
        }
        finally
        {
            try { key.Destroy(); } catch { /* best-effort cleanup */ }
        }
    }
}
