# Spec Delta

## MODIFIED Requirements

### Requirement: Validate native parameters without downgrade

A native TLS-capable adapter SHALL load system roots by default, apply the configured ordered truststore source list, and fail preparation when any source cannot be read or parsed. TLS verification SHALL remain enabled unless an explicit insecure option is selected, and validation failure SHALL NOT fall back to plaintext or another protocol.

#### Scenario: Intrinsic TLS has no explicit TLS block

- **WHEN** a Hysteria2, TUIC, AnyTLS, or other intrinsically TLS node omits explicit TLS options
- **THEN** the adapter still uses system roots by default and performs certificate validation

#### Scenario: Requested TLS configuration fails

- **WHEN** validation of a node's requested TLS configuration fails
- **THEN** the node is rejected or remains unavailable with a typed diagnostic, and no plaintext or direct fallback is selected

## ADDED Requirements

### Requirement: Truststore source lists are atomic

An adapter SHALL process truststore sources as one atomic set. Sources SHALL be `system` or local PEM/DER certificate files; relative paths SHALL resolve from the selected configuration source, symlink targets SHALL be regular files, and any invalid source SHALL reject the adapter candidate.

#### Scenario: One source in a list is invalid

- **WHEN** one configured truststore source is unreadable, oversized, malformed, or contains no valid certificate
- **THEN** adapter preparation fails closed without silently removing the invalid source or restoring system roots

### Requirement: Explicit insecure verification is separate

An adapter SHALL skip certificate verification only when its TLS options explicitly request insecure verification. An empty truststore without that option SHALL fail closed, and a TLS failure SHALL never downgrade to plaintext.

#### Scenario: Custom roots do not validate the peer

- **WHEN** a node uses a custom truststore and the peer certificate is not anchored by it
- **THEN** the TLS connection fails with a typed adapter error and does not retry as plaintext or insecure TLS
