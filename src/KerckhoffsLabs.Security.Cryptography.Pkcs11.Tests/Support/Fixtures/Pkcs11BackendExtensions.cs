// Licensed under the MIT License

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

internal static class Pkcs11BackendExtensions
{
    /// <summary>
    /// Skips the test when the backend does not advertise <paramref name="mechanism"/> in its
    /// <c>C_GetMechanismList</c>. Lets one shared test case run on every backend that supports the
    /// mechanism and skip cleanly on those that do not — e.g. a v2.40 SoftHSM 2.5 that predates
    /// EdDSA, rather than failing with <c>CKR_MECHANISM_INVALID</c>.
    /// </summary>
    internal static void RequireMechanism(this IPkcs11Backend backend, CKM mechanism)
    {
        if (!backend.Supports(mechanism))
            throw new SkipTestException($"Backend does not advertise {mechanism}.");
    }
}
