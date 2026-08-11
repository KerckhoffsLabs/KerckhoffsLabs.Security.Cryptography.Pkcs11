// -------------------------------------------------------------------------------------------
// Assembly-wide test-parallelization policy — stated explicitly rather than inherited from the
// xUnit defaults, because the safety of this suite depends on it.
//
// CollectionPerClass + parallelization enabled means: a test class that declares no
// [Collection(...)] gets a private collection of its own and runs CONCURRENTLY with every other
// collection. That is the right default for the hermetic Unit/ tests, but it is also the failure
// mode for the backend suites: pkcs11-mock is single-session and process-global, and the SoftHSM /
// NSS / opencryptoki fixtures own one C_Initialize'd module each. A backend test class that
// forgets its [Collection] therefore does not fail loudly — it races the collection that owns the
// module and corrupts shared native state intermittently.
//
// Two things keep that from happening, and neither is the runner configuration:
//   * the per-backend [CollectionDefinition]s in Support/Fixtures, which serialize each backend's
//     tests and own the module lifetime;
//   * TestCollectionConventionTests, which fails the build when a test class under Integration/
//     carries neither a [Collection] nor an explicit [NoBackendCollection] opt-out.
//
// Do not switch this to CollectionPerAssembly as a "safety" measure: classes with an explicit
// [Collection] would still run in parallel with the default collection, so the race would survive
// while every hermetic unit test got serialized. Keep the fast default and keep the guardrail.
// -------------------------------------------------------------------------------------------

[assembly: CollectionBehavior(CollectionBehavior.CollectionPerClass, DisableTestParallelization = false)]
