# PathChord Quinn patch

This directory is based on the crates.io `quinn-proto` 0.11.19 release,
SHA-256 `0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe`.
The original MIT and Apache-2.0 license files are retained. `Cargo.toml` is the
published, normalized manifest. The workspace patches this exact crate version.

The following default-off extension points let the Hysteria2 adapter implement
the Brutal controller without changing the selected controller for other users:

- `Controller::can_send` defaults to Quinn's original window check and supplies
  the current RTT and unfinished packet size to opt-in controllers.
- `Controller::pacing_deadline` defaults to Quinn's original pacer. A controller
  may own pacing and account for every encoded packet with
  `Controller::on_packet_transmitted`.
- Each sent packet records the controller's opaque context, which accompanies
  its ACK and loss notifications. Hysteria2 uses it to exclude packets sent
  before the BBR-to-Brutal switch, even when delivery or loss is reported later.
  `Controller::on_packet_lost` reports individual lost ACK-eliciting packets,
  including MTU probes and excluding ECN-only events; packet counts are not
  estimated from aggregate lost bytes. Default ACK handling is unchanged.
- `RttEstimator::smoothed` exposes whether an RTT sample has been established.

The Hysteria2 controller and tests live in `crates/pathchord-transit`; the
upstream source comparison and test scope are recorded in the change research
`openspec/changes/support-sing-box-dae-transit-protocols/research/2026-11-16-hysteria2-brutal-pacing.md`.
Reassess this patch whenever upgrading Quinn; prefer upstream equivalents if
they become available. The independent-pacer hook is not enabled for TUIC or
other Quinn users.
