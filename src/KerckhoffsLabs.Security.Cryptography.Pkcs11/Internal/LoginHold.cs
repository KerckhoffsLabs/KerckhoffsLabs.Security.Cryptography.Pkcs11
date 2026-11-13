namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// One holder's share of a token login: while any hold of the current login is undisposed, the login is
/// not logged out. Handed out by <see cref="TokenLoginRecord.Login"/> and <see cref="TokenLoginRecord.Share"/>.
/// </summary>
/// <remarks>
/// Disposing it releases the share once; the last share of the current login to go sends <c>C_Logout</c>.
/// A hold of a login that has since ended (the module reported it gone, see
/// <see cref="TokenLoginRecord.MarkEnded"/>) is inactive and releasing it sends nothing.
/// </remarks>
internal sealed class LoginHold : IDisposable
{
    private int _released;

    internal LoginHold(TokenLoginRecord record, Pkcs11Library owner, long generation)
    {
        Record = record;
        Owner = owner;
        Generation = generation;
    }

    /// <summary>The login this is a share of.</summary>
    public TokenLoginRecord Record { get; }

    /// <summary>The login generation this share was taken in.</summary>
    public long Generation { get; }

    /// <summary>The library this share came through; disposing that library releases it.</summary>
    public Pkcs11Library Owner { get; }

    /// <summary>
    /// Whether this share is still held and its login is the current one: not released, not logged out, and
    /// not reported ended by the module.
    /// </summary>
    public bool IsActive => !IsReleased && Record.IsCurrent(Generation);

    /// <summary>Whether this share has been released, by <see cref="Dispose"/> or by its library's disposal.</summary>
    internal bool IsReleased => Volatile.Read(ref _released) != 0;

    /// <summary>Marks this share released; <see langword="true"/> only for the call that did.</summary>
    internal bool TryMarkReleased() => Interlocked.Exchange(ref _released, 1) == 0;

    /// <summary>Releases this share, once; the last share of the current login logs it out.</summary>
    /// <exception cref="InvalidOperationException">
    /// Called from inside an operation on the token (<see cref="TokenLoginRecord.EnterOperation"/>). Nothing is
    /// released then: the share stays held, and releasing it once the operation is over still logs out.
    /// </exception>
    public void Dispose()
    {
        if (IsReleased)
            return;
        Record.ThrowIfInsideOperation();
        if (TryMarkReleased())
            Record.Release(this);
    }
}
