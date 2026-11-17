# Verified subscription nodes

This investigation records a validation boundary for subscription nodes. It
does not contain provider documents, node identities, addresses or credentials.
The proposed changes remain pending until implemented and tested.

## Finding

The importer can currently classify a node as `Active` based on the available
protocol names. A nonempty but malformed credential, an unsupported TLS
fingerprint, or an unimplemented packet encoding can therefore appear in
`DynamicTransitSnapshot::selectable_nodes()` before an adapter has accepted
its complete configuration. `extend_runtime_catalog()` also advertises TCP
and UDP for every such node, independent of the adapter's actual capabilities.
Cache reload reconstructs the same state from the protocol name and stored
diagnostic; it does not prove that the current backend can prepare the node.

The CLI's current `publish_dynamic_transit` path separately builds and
prepares each adapter before registering it with the data plane, and marks a
failed build down. This protects that path, but does not make the public
snapshot's selectable set or catalog extension an independently verified
admission result. A cached private sing-box outbound which was previously
unsupported also remains unavailable after an importer improvement until it
is re-normalized or freshly fetched.

## Proposed boundary

1. Represent a syntactically accepted import or cache entry as a pending
   candidate. Keep malformed and unsupported entries unavailable with their
   existing sanitized diagnostics; do not discard valid siblings. A protocol
   name or a persisted cache record alone must not make a candidate selectable.
2. Prepare candidates through the configured `AdapterRegistry`, using the
   complete typed configuration and private credentials. Build the adapter,
   run its bounded `prepare()` operation, and retain that exact adapter together
   with its effective TCP/UDP capabilities. A failed or timed-out preparation
   yields a bounded, sanitized diagnostic. Do not expose credential values or
   raw documents in errors, logs or identifiers.
3. Return an opaque preparation result bound to the source identity, the
   captured subscription snapshot generation, and the complete candidate
   identity, including its private credentials. Before publication, verify
   that the source is still enabled, the relevant control/configuration
   generation has not changed, and the candidate has not been replaced. Drop
   stale results without installing an adapter or changing the newer node.
   Compare private values without rendering them in a diagnostic.
4. Expose selectable nodes and a policy runtime catalog only from a verified
   snapshot or an equivalent unforgeable admission handle. A caller must not
   be able to make an unverified configuration selectable by changing a
   publicly writable state field, or by changing the configuration after
   validation. Capabilities reflect both the retained adapter and explicit
   per-node restrictions. The CLI installs the retained adapter itself; it
   must not validate one instance and then independently build another.
5. Publish the result and the corresponding runtime registration under the
   existing source and configuration fences. Registration needs an observable
   success, blocked-source, or static-ID-conflict outcome so the verified
   view cannot claim an adapter was installed when registration refused it.
   Keep slow preparation outside long-lived control locks, then recheck the
   fences immediately before installation. Cancellation must not leave a
   candidate selectable or publish a late result.
6. Persist private configuration, credentials, source binding and import
   diagnostics as today; do not persist an adapter-validation success.
   Every cache load must prepare against the current registry before admission.
   A stale private fallback document may be re-normalized in memory if its
   source binding and node identity can be retained safely; otherwise keep it
   unavailable until a successful refresh. Preserve existing cache source,
   age, credential-origin and atomicity checks.

A fetch or validation failure must not silently replace a still-current
verified snapshot with partial data. An explicitly disabled or replaced
source remains fenced: existing admitted flows may drain, but an old adapter
must not admit new work for the replacement. If a newly accepted candidate
with changed credentials fails preparation, it must not silently reuse the
previous candidate's adapter.

## Compatibility and sequencing

`SubscriptionManager::new` and the current public node and snapshot types
are used by existing tests and callers. Introducing a pending state or moving
selection methods to an opaque verified type changes their semantics and may
affect exhaustive state matches. Review callers and migrate them explicitly;
do not preserve the old behavior by treating a protocol-name check as proof.
Validation results should be committed as a generation-bound batch so that
marking one successful node does not invalidate other results prepared from
the same snapshot. The runtime may still publish individual nodes under its
existing configuration gate after the batch and source have been rechecked.

This work is intentionally separate from the current provider acceptance
run. The existing CLI's adapter build and data-plane validation remain in
place until the replacement is integrated and verified end to end.

## Behavioral validation plan

- Import a valid node alongside nodes with a malformed UUID, unsupported
  fingerprint, and unsupported packet encoding. Only the successfully prepared
  node is selectable or ready in the policy catalog; diagnostics remain
  sanitized and valid siblings survive.
- Verify a TCP-only adapter and a node with UDP explicitly disabled advertise
  only their actual effective capabilities, including after cache reload.
- Restore a cache with a changed or unavailable backend, or changed
  credentials, and verify that no prior validation result is inherited.
  Verify an old private fallback stays unavailable until safely re-normalized
  or refreshed.
- Block preparation with a synchronization primitive, then disable the source
  or replace the same node ID and credentials. Releasing the old preparation
  must not install the old adapter or mark the replacement ready. A fresh
  preparation can subsequently admit the current node.
- Exercise preparation failure, timeout and cancellation, a static-ID
  registration conflict, and concurrent refresh. Check source/generation
  fences, stable redacted diagnostics and absence of a late or direct fallback.
  Previously admitted streams may finish while new admissions follow the
  current source state.
