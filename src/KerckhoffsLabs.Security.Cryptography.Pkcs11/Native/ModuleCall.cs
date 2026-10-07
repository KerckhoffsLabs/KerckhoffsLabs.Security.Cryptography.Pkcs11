using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.SafeHandles;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// A use of a <see cref="Pkcs11ModuleHandle"/> for the duration of one call into the module.
/// Taking it throws <see cref="ObjectDisposedException"/> once the module has been disposed; while it
/// is held, the module cannot be unmapped, nor — unless it is a blocking wait — finalized. A module that
/// may not be called concurrently is also locked for the call's duration.
/// </summary>
internal ref struct ModuleCall
{
    private readonly Pkcs11ModuleHandle _module;
    private readonly bool _holdsOffFinalize;
    private bool _added;
    private bool _serialized;

    internal ModuleCall(Pkcs11ModuleHandle module, bool holdsOffFinalize)
    {
        _module = module;
        _holdsOffFinalize = holdsOffFinalize;
        _added = false;
        module.AddUse(ref _added, holdsOffFinalize);
        _serialized = module.EnterCall();
    }

    /// <summary>The module's function table.</summary>
    public readonly Delegates Table => _module.Table;

    public void Dispose()
    {
        // The call lock first: releasing the use can run C_Finalize, which takes the registry lock.
        if (_serialized)
        {
            _serialized = false;
            _module.ExitCall();
        }
        if (_added)
        {
            _added = false;
            _module.ReleaseUse(_holdsOffFinalize);
        }
    }
}
