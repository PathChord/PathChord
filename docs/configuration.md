# PathChord Configuration Model

This is a conceptual model. Exact serialization is not fixed.

## Static Egress topology

```yaml
egresses:
  - id: jp-1
    address: egress.example.net
    port: 443
    public_key: <curve25519-public-key>
    labels:
      region: jp
      role: egress
    capabilities:
      tcp: true
      udp: true
```

## Dynamic Transit Proxy data

```yaml
transit_proxies:
  - id: provider-a-node-01
    source:
      type: clash
      subscription: provider-a
    protocol: vless
    address: proxy.example.net
    port: 443
    labels:
      region: jp
      provider: provider-a
    tags: [gaming]
    weight: 100
```

Runtime fields are maintained separately:

```yaml
observed:
  connected: true
  rtt_ms: 42
  jitter_ms: 5
  loss_rate: 0.002
  effective_capacity_bps: 180000000
quota:
  remaining_ratio: 0.42
  reset_at: 2026-12-01T00:00:00Z
billing:
  traffic_multiplier: 2.0
```

## Ordered Egress rules

```yaml
egress_rules:
  - id: jp-gaming
    match:
      flow_tags: [gaming]
      protocol: [tcp, udp]
    egress: jp-1
    requirements:
      min_usable_paths: 1
```

The first rule whose conditions match and whose Egress is currently usable wins. Egress usability is precomputed by the runtime state manager.

## Egress-specific Proxy rules

```yaml
transit_rules:
  - id: jp-1-gaming
    egress: jp-1
    match:
      flow_tags: [gaming]
    require:
      labels:
        region: jp
      capabilities: [udp]
    reject:
      tags: [quota-exhausted]
    weight: 100
```

Rules are ordered. The first matching rule determines admission and base relationship weight.

## Ordinary Proxy rules and fallback

```yaml
proxy_rules:
  - id: direct-jp
    match:
      flow_tags: [web]
    require:
      labels:
        region: jp
    select: any

fallback:
  action: reject # or direct
```

Selection order is:

```text
ordered effective Egress rules
→ ordered ordinary Proxy rules
→ mandatory global fallback
```

## Listeners

```yaml
listeners:
  - id: lan-socks
    type: socks5
    bind: 0.0.0.0:1080
    allowed_sources: [192.168.1.0/24]
    authentication: required

  - id: local-http
    type: http
    bind: 127.0.0.1:8080
    authentication: disabled
```

`listener_id`, source address, authentication identity, process metadata, protocol, and target address are available to rules.
