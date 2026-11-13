//! Path transport boundaries and deterministic fault-injection fixtures.
//!
//! The protocol core exchanges owned, complete frame values through
//! [`CompleteFrameTransport`]. Byte-stream segmentation, reassembly, record
//! authentication, and corruption detection must happen below this boundary.

use std::collections::{BTreeMap, VecDeque};

use async_trait::async_trait;
use pathchord_core::PathFrame;
use thiserror::Error;

mod single_path;

pub use single_path::{
    AuthorizationState, PathAuthorization, SinglePathError, SinglePathHandshakeConfig,
    SinglePathOutcome, SinglePathReady, establish_single_path,
};

/// An asynchronous transport whose smallest delivery unit is one complete
/// PathChord frame.
///
/// The absence of byte/chunk methods prevents adapters from exposing partial
/// frames to Session and Stream logic.
#[async_trait]
pub trait CompleteFrameTransport: Send {
    /// Adapter-specific failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Sends one complete frame.
    async fn send_frame(&mut self, frame: PathFrame) -> Result<(), Self::Error>;

    /// Receives one complete frame, or `None` when none is currently available.
    async fn receive_frame(&mut self) -> Result<Option<PathFrame>, Self::Error>;
}

/// Fault applied to a particular zero-based send ordinal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultAction {
    /// Discard the complete frame.
    Drop,

    /// Deliver the complete frame once plus the requested extra copies.
    Duplicate {
        /// Number of injected copies after the original delivery.
        extra_copies: u8,
    },

    /// Hold this frame until a later normally delivered or duplicated frame has
    /// been queued, producing deterministic out-of-order delivery.
    Reorder,

    /// Emulate corruption detected by record authentication or frame decoding.
    /// The damaged frame is discarded below the complete-frame boundary.
    Corrupt,
}

/// Deterministic mapping from send ordinal to an injected fault.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FaultPlan {
    actions: BTreeMap<u64, FaultAction>,
}

impl FaultPlan {
    /// Adds or replaces the fault for one zero-based send ordinal.
    #[must_use]
    pub fn on_send(mut self, ordinal: u64, action: FaultAction) -> Self {
        self.actions.insert(ordinal, action);
        self
    }

    /// Returns the configured action for a send ordinal.
    #[must_use]
    pub fn action_for(&self, ordinal: u64) -> Option<FaultAction> {
        self.actions.get(&ordinal).copied()
    }
}

/// Counters exposed by [`FakeTransit`] for deterministic assertions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FakeTransitStats {
    /// Complete frames submitted by the sender.
    pub frames_sent: u64,
    /// Complete frame values queued for delivery, including injected copies.
    pub frames_queued: u64,
    /// Complete frames returned to the receiver.
    pub frames_received: u64,
    /// Frames deliberately dropped by a `Drop` fault.
    pub frames_dropped: u64,
    /// Damaged frames rejected below the complete-frame boundary.
    pub corrupted_frames_rejected: u64,
    /// Additional frame copies injected by duplicate faults.
    pub duplicate_copies_injected: u64,
    /// Frames delayed to create out-of-order delivery.
    pub frames_reordered: u64,
}

/// Errors returned by [`FakeTransit`].
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum FakeTransitError {
    /// A frame was submitted after the fixture was closed.
    #[error("fake Transit is closed")]
    Closed,

    /// The zero-based send ordinal exhausted its `u64` representation.
    #[error("fake Transit send ordinal exhausted")]
    SendOrdinalExhausted,
}

/// In-memory complete-frame transport with an ordinal-based fault plan.
///
/// Corruption is modeled as detection and rejection below this abstraction, so
/// a caller can observe loss but can never receive a modified or partial frame.
#[derive(Debug)]
pub struct FakeTransit {
    plan: FaultPlan,
    next_send_ordinal: u64,
    ready: VecDeque<PathFrame>,
    reordered: VecDeque<PathFrame>,
    stats: FakeTransitStats,
    closed: bool,
}

impl FakeTransit {
    /// Creates an open fixture with the supplied deterministic fault plan.
    #[must_use]
    pub fn new(plan: FaultPlan) -> Self {
        Self {
            plan,
            next_send_ordinal: 0,
            ready: VecDeque::new(),
            reordered: VecDeque::new(),
            stats: FakeTransitStats::default(),
            closed: false,
        }
    }

    /// Returns current counters without mutating transport state.
    #[must_use]
    pub const fn stats(&self) -> FakeTransitStats {
        self.stats
    }

    /// Releases any frames still held by `Reorder` actions in original order.
    ///
    /// This is useful when a trace ends without a following frame that would
    /// naturally trigger release.
    pub fn flush_reordered(&mut self) {
        while let Some(frame) = self.reordered.pop_front() {
            self.queue(frame);
        }
    }

    /// Prevents further sends. Already queued frames remain receivable.
    pub fn close(&mut self) {
        self.closed = true;
    }

    fn queue(&mut self, frame: PathFrame) {
        self.ready.push_back(frame);
        self.stats.frames_queued += 1;
    }

    fn release_reordered(&mut self) {
        while let Some(frame) = self.reordered.pop_front() {
            self.queue(frame);
        }
    }
}

impl Default for FakeTransit {
    fn default() -> Self {
        Self::new(FaultPlan::default())
    }
}

#[async_trait]
impl CompleteFrameTransport for FakeTransit {
    type Error = FakeTransitError;

    async fn send_frame(&mut self, frame: PathFrame) -> Result<(), Self::Error> {
        if self.closed {
            return Err(FakeTransitError::Closed);
        }

        let ordinal = self.next_send_ordinal;
        self.next_send_ordinal = self
            .next_send_ordinal
            .checked_add(1)
            .ok_or(FakeTransitError::SendOrdinalExhausted)?;
        self.stats.frames_sent += 1;

        match self.plan.action_for(ordinal) {
            Some(FaultAction::Drop) => {
                self.stats.frames_dropped += 1;
            }
            Some(FaultAction::Corrupt) => {
                self.stats.corrupted_frames_rejected += 1;
            }
            Some(FaultAction::Reorder) => {
                self.reordered.push_back(frame);
                self.stats.frames_reordered += 1;
            }
            Some(FaultAction::Duplicate { extra_copies }) => {
                self.queue(frame.clone());
                for _ in 0..extra_copies {
                    self.queue(frame.clone());
                    self.stats.duplicate_copies_injected += 1;
                }
                self.release_reordered();
            }
            None => {
                self.queue(frame);
                self.release_reordered();
            }
        }

        Ok(())
    }

    async fn receive_frame(&mut self) -> Result<Option<PathFrame>, Self::Error> {
        let frame = self.ready.pop_front();
        if frame.is_some() {
            self.stats.frames_received += 1;
        }
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathchord_core::{FrameFlags, FrameType, PathId, ProtocolLimits, SessionId};

    fn frame(sequence: u8) -> PathFrame {
        PathFrame::new(
            FrameType::Heartbeat,
            FrameFlags::empty(),
            SessionId::new(1),
            PathId::new(2),
            u64::from(sequence),
            vec![sequence; usize::from(sequence) + 1],
            ProtocolLimits::default(),
        )
        .expect("valid test frame")
    }

    #[tokio::test]
    async fn transports_a_complete_frame_as_one_delivery_unit() {
        let expected = frame(3);
        let mut transit = FakeTransit::default();

        transit
            .send_frame(expected.clone())
            .await
            .expect("send complete frame");

        assert_eq!(
            transit.receive_frame().await.expect("receive frame"),
            Some(expected)
        );
        assert_eq!(transit.receive_frame().await.expect("empty queue"), None);
    }

    #[tokio::test]
    async fn drops_only_the_selected_whole_frame() {
        let plan = FaultPlan::default().on_send(1, FaultAction::Drop);
        let mut transit = FakeTransit::new(plan);

        for sequence in 0..3 {
            transit
                .send_frame(frame(sequence))
                .await
                .expect("send frame");
        }

        assert_eq!(
            transit.receive_frame().await.expect("first frame"),
            Some(frame(0))
        );
        assert_eq!(
            transit.receive_frame().await.expect("third frame"),
            Some(frame(2))
        );
        assert_eq!(transit.stats().frames_dropped, 1);
    }

    #[tokio::test]
    async fn duplicates_a_whole_frame_deterministically() {
        let plan = FaultPlan::default().on_send(0, FaultAction::Duplicate { extra_copies: 2 });
        let mut transit = FakeTransit::new(plan);
        let expected = frame(4);

        transit
            .send_frame(expected.clone())
            .await
            .expect("send frame");

        for _ in 0..3 {
            assert_eq!(
                transit.receive_frame().await.expect("duplicated frame"),
                Some(expected.clone())
            );
        }
        assert_eq!(transit.stats().duplicate_copies_injected, 2);
    }

    #[tokio::test]
    async fn reorders_whole_frames_without_modifying_them() {
        let plan = FaultPlan::default().on_send(0, FaultAction::Reorder);
        let mut transit = FakeTransit::new(plan);

        transit.send_frame(frame(0)).await.expect("held frame");
        assert_eq!(transit.receive_frame().await.expect("nothing ready"), None);

        transit.send_frame(frame(1)).await.expect("later frame");
        assert_eq!(
            transit.receive_frame().await.expect("later first"),
            Some(frame(1))
        );
        assert_eq!(
            transit.receive_frame().await.expect("held second"),
            Some(frame(0))
        );
        assert_eq!(transit.stats().frames_reordered, 1);
    }

    #[tokio::test]
    async fn corruption_is_rejected_below_the_frame_boundary() {
        let plan = FaultPlan::default().on_send(0, FaultAction::Corrupt);
        let mut transit = FakeTransit::new(plan);

        transit
            .send_frame(frame(0))
            .await
            .expect("inject corrupted frame");

        assert_eq!(
            transit.receive_frame().await.expect("no damaged frame"),
            None
        );
        assert_eq!(transit.stats().corrupted_frames_rejected, 1);
        assert_eq!(transit.stats().frames_queued, 0);
    }
}
