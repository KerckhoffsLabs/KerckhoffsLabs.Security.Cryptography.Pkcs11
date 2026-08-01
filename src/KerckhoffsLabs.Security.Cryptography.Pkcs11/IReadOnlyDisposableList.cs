namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// A read-only list whose elements are released when the list is disposed, so a caller can hold a
/// returned collection of disposables in a <c>using</c> without also being handed the ability to
/// change it.
/// </summary>
/// <remarks>
/// <para>
/// This is the type to return from a public API. It says the two things a caller needs — the
/// collection is theirs to dispose, and it is not theirs to modify — where a bare
/// <see cref="IReadOnlyList{T}"/> says only the second and leaves the elements to be released by
/// hand, one loop per call site.
/// </para>
/// <para>
/// Disposing releases every element, including when one of them throws; see
/// <see cref="DisposableList{T}"/>, the implementation this library builds.
/// </para>
/// </remarks>
/// <typeparam name="T">Element type; every element is released when the list is disposed.</typeparam>
public interface IReadOnlyDisposableList<out T> : IReadOnlyList<T>, IDisposable
    where T : IDisposable
{
}
