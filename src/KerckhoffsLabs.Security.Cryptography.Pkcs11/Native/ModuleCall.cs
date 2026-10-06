using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// A use of a <see cref="Pkcs11ModuleHandle"/> for the duration of one call into the module.
/// Taking it throws <see cref="ObjectDisposedException"/> once the module has been disposed; while it
/// is held, the module cannot be unmapped, nor — unless it is a blocking wait — finalized.
/// </summary>
internal ref struct ModuleCall
{
    private readonly Pkcs11ModuleHandle _module;
    private readonly bool _holdsOffFinalize;
    private bool _added;

    internal ModuleCall(Pkcs11ModuleHandle module, bool holdsOffFinalize)
    {
        _module = module;
        _holdsOffFinalize = holdsOffFinalize;
        _added = false;
        module.AddUse(ref _added, holdsOffFinalize);
    }

    /// <summary>The module's function table.</summary>
    public readonly Delegates Table => _module.Table;

    public void Dispose()
    {
        if (_added)
        {
            _added = false;
            _module.ReleaseUse(_holdsOffFinalize);
        }
    }
}
