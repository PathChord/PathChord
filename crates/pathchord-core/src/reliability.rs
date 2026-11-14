//! Synchronous Phase-1 reliability primitives.
//!
//! These types deliberately stop below sockets and task scheduling. They model
//! sequence allocation, cumulative/selective acknowledgements, at-most-once
//! control application, and bounded TCP byte reordering.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::varint::MAX_VARINT;

/// An inclusive byte or control sequence range.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AckRange {
    pub start: u64,
    pub end: u64,
}

impl AckRange {
    pub const fn validate(self) -> Result<(), ReliabilityError> {
        if self.start <= self.end && self.end <= MAX_VARINT {
            Ok(())
        } else {
            Err(ReliabilityError::InvalidRange {
                start: self.start,
                end: self.end,
            })
        }
    }

    pub const fn contains(self, value: u64) -> bool {
        value >= self.start && value <= self.end
    }
}

/// Sender-owned bounded control retransmission state.
#[derive(Debug)]
pub struct ControlSender<T> {
    next_sequence: u64,
    max_pending: usize,
    pending: BTreeMap<u64, T>,
}

impl<T> ControlSender<T> {
    pub fn new(max_pending: usize) -> Result<Self, ReliabilityError> {
        if max_pending == 0 {
            return Err(ReliabilityError::ZeroCapacity);
        }
        Ok(Self {
            next_sequence: 0,
            max_pending,
            pending: BTreeMap::new(),
        })
    }

    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn enqueue(&mut self, payload: T) -> Result<u64, ReliabilityError> {
        if self.pending.len() >= self.max_pending {
            return Err(ReliabilityError::QueueFull {
                capacity: self.max_pending,
            });
        }
        if self.next_sequence > MAX_VARINT {
            return Err(ReliabilityError::SequenceExhausted);
        }
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ReliabilityError::SequenceExhausted)?;
        self.pending.insert(sequence, payload);
        Ok(sequence)
    }

    pub fn acknowledge(&mut self, highest_contiguous: u64, ranges: &[AckRange]) -> usize {
        let mut acknowledged = BTreeSet::new();
        for sequence in self.pending.keys().copied() {
            if sequence <= highest_contiguous || ranges.iter().any(|range| range.contains(sequence))
            {
                acknowledged.insert(sequence);
            }
        }
        let count = acknowledged.len();
        for sequence in acknowledged {
            self.pending.remove(&sequence);
        }
        count
    }

    pub fn pending(&self) -> impl Iterator<Item = (u64, &T)> {
        self.pending
            .iter()
            .map(|(sequence, payload)| (*sequence, payload))
    }

    pub fn pending_mut(&mut self) -> impl Iterator<Item = (u64, &mut T)> {
        self.pending
            .iter_mut()
            .map(|(sequence, payload)| (*sequence, payload))
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

/// Receiver-side at-most-once control sequence application state.
#[derive(Debug)]
pub struct ControlReceiver {
    max_applied: usize,
    applied: BTreeSet<u64>,
    highest_contiguous: Option<u64>,
}

impl ControlReceiver {
    pub fn new(max_applied: usize) -> Result<Self, ReliabilityError> {
        if max_applied == 0 {
            return Err(ReliabilityError::ZeroCapacity);
        }
        Ok(Self {
            max_applied,
            applied: BTreeSet::new(),
            highest_contiguous: None,
        })
    }

    /// Returns `true` only for a new sequence that should execute once.
    pub fn apply(&mut self, sequence: u64) -> Result<bool, ReliabilityError> {
        if sequence > MAX_VARINT {
            return Err(ReliabilityError::SequenceOutOfRange { sequence });
        }
        if self
            .highest_contiguous
            .is_some_and(|highest| sequence <= highest)
        {
            return Ok(false);
        }
        if self.applied.contains(&sequence) {
            return Ok(false);
        }
        if self.applied.len() >= self.max_applied {
            return Err(ReliabilityError::QueueFull {
                capacity: self.max_applied,
            });
        }
        self.applied.insert(sequence);
        let mut next = self.highest_contiguous.map_or(0, |value| value + 1);
        while self.applied.remove(&next) {
            self.highest_contiguous = Some(next);
            next = next
                .checked_add(1)
                .ok_or(ReliabilityError::SequenceExhausted)?;
        }
        Ok(true)
    }

    pub const fn highest_contiguous(&self) -> Option<u64> {
        self.highest_contiguous
    }

    pub fn selective_ranges(&self) -> Vec<AckRange> {
        let mut ranges = Vec::new();
        let mut current: Option<AckRange> = None;
        for sequence in self.applied.iter().copied() {
            current = match current {
                None => Some(AckRange {
                    start: sequence,
                    end: sequence,
                }),
                Some(range) if sequence == range.end + 1 => Some(AckRange {
                    start: range.start,
                    end: sequence,
                }),
                Some(range) => {
                    ranges.push(range);
                    Some(AckRange {
                        start: sequence,
                        end: sequence,
                    })
                }
            };
        }
        if let Some(range) = current {
            ranges.push(range);
        }
        ranges
    }
}

/// Result of inserting a reliable Stream data range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamInsertResult {
    pub delivered: Vec<u8>,
    pub duplicate: bool,
}

/// Bounded offset-aware receive buffer for one TCP Stream direction.
#[derive(Debug)]
pub struct StreamReceiveBuffer {
    next_offset: u64,
    max_buffered: usize,
    buffered: usize,
    segments: BTreeMap<u64, Vec<u8>>,
}

impl StreamReceiveBuffer {
    pub fn new(max_buffered: usize) -> Result<Self, ReliabilityError> {
        if max_buffered == 0 {
            return Err(ReliabilityError::ZeroCapacity);
        }
        Ok(Self {
            next_offset: 0,
            max_buffered,
            buffered: 0,
            segments: BTreeMap::new(),
        })
    }

    pub const fn next_offset(&self) -> u64 {
        self.next_offset
    }

    pub const fn buffered_bytes(&self) -> usize {
        self.buffered
    }

    /// Validates overlapping bytes and returns the not-yet-received ranges as
    /// half-open offsets. This lets the caller reserve exactly the memory that
    /// insertion requires, including for partially overlapping retransmissions.
    pub fn missing_ranges(
        &self,
        offset: u64,
        data: &[u8],
    ) -> Result<Vec<(u64, u64)>, ReliabilityError> {
        if offset > MAX_VARINT {
            return Err(ReliabilityError::OffsetOutOfRange { offset });
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(ReliabilityError::OffsetOverflow)?;
        if end > MAX_VARINT + 1 {
            return Err(ReliabilityError::OffsetOutOfRange { offset: end });
        }
        let start = offset.max(self.next_offset);
        if start >= end {
            return Ok(Vec::new());
        }
        let mut cursor = start;
        let mut missing = Vec::new();
        for (&existing_start, existing) in self.segments.range(..end) {
            let existing_end = existing_start + existing.len() as u64;
            if existing_end <= start {
                continue;
            }
            if cursor < existing_start {
                missing.push((cursor, existing_start.min(end)));
            }
            let overlap_start = start.max(existing_start);
            let overlap_end = end.min(existing_end);
            if overlap_start < overlap_end {
                let incoming_start = (overlap_start - offset) as usize;
                let stored_start = (overlap_start - existing_start) as usize;
                let length = (overlap_end - overlap_start) as usize;
                if let Some(difference) = data[incoming_start..incoming_start + length]
                    .iter()
                    .zip(&existing[stored_start..stored_start + length])
                    .position(|(incoming, stored)| incoming != stored)
                {
                    return Err(ReliabilityError::ConflictingOverlap {
                        offset: overlap_start + difference as u64,
                    });
                }
            }
            cursor = cursor.max(existing_end);
            if cursor >= end {
                break;
            }
        }
        if cursor < end {
            missing.push((cursor, end));
        }
        let additional: usize = missing
            .iter()
            .map(|(start, end)| (end - start) as usize)
            .sum();
        if self.buffered.saturating_add(additional) > self.max_buffered {
            return Err(ReliabilityError::QueueFull {
                capacity: self.max_buffered,
            });
        }
        Ok(missing)
    }

    /// Inserts every missing subrange and returns the newly contiguous prefix.
    /// Identical retransmissions do not consume capacity; conflicting buffered
    /// overlaps are rejected before any state is changed.
    pub fn insert(
        &mut self,
        offset: u64,
        data: &[u8],
    ) -> Result<StreamInsertResult, ReliabilityError> {
        let missing = self.missing_ranges(offset, data)?;
        let additional: usize = missing
            .iter()
            .map(|(start, end)| (end - start) as usize)
            .sum();
        let duplicate = additional < data.len();
        for (start, end) in missing {
            let from = (start - offset) as usize;
            let to = (end - offset) as usize;
            self.segments.insert(start, data[from..to].to_vec());
            self.buffered += to - from;
        }
        let mut delivered = Vec::new();
        while let Some((&segment_start, _)) = self.segments.first_key_value() {
            if segment_start != self.next_offset {
                break;
            }
            let segment = self.segments.pop_first().expect("first segment exists").1;
            self.buffered -= segment.len();
            self.next_offset += segment.len() as u64;
            delivered.extend_from_slice(&segment);
        }
        Ok(StreamInsertResult {
            delivered,
            duplicate,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReliabilityError {
    ZeroCapacity,
    QueueFull { capacity: usize },
    SequenceExhausted,
    SequenceOutOfRange { sequence: u64 },
    InvalidRange { start: u64, end: u64 },
    OffsetOutOfRange { offset: u64 },
    OffsetOverflow,
    ConflictingOverlap { offset: u64 },
}

impl fmt::Display for ReliabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCapacity => formatter.write_str("reliability capacity must be non-zero"),
            Self::QueueFull { capacity } => {
                write!(formatter, "reliability queue is full ({capacity})")
            }
            Self::SequenceExhausted => formatter.write_str("reliability sequence space exhausted"),
            Self::SequenceOutOfRange { sequence } => {
                write!(formatter, "sequence {sequence} exceeds 62 bits")
            }
            Self::InvalidRange { start, end } => {
                write!(formatter, "invalid inclusive range {start}..={end}")
            }
            Self::OffsetOutOfRange { offset } => {
                write!(formatter, "Stream offset {offset} exceeds 62 bits")
            }
            Self::OffsetOverflow => formatter.write_str("Stream offset arithmetic overflowed"),
            Self::ConflictingOverlap { offset } => {
                write!(formatter, "conflicting Stream bytes at offset {offset}")
            }
        }
    }
}

impl std::error::Error for ReliabilityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_sender_retains_until_acknowledged() {
        let mut sender = ControlSender::new(2).unwrap();
        assert_eq!(sender.enqueue("a"), Ok(0));
        assert_eq!(sender.enqueue("b"), Ok(1));
        assert_eq!(
            sender.enqueue("c"),
            Err(ReliabilityError::QueueFull { capacity: 2 })
        );
        assert_eq!(sender.acknowledge(0, &[]), 1);
        assert_eq!(sender.pending_len(), 1);
    }

    #[test]
    fn control_receiver_applies_each_sequence_once_and_reports_gaps() {
        let mut receiver = ControlReceiver::new(8).unwrap();
        assert_eq!(receiver.apply(2), Ok(true));
        assert_eq!(receiver.highest_contiguous(), None);
        assert_eq!(receiver.apply(2), Ok(false));
        assert_eq!(receiver.apply(0), Ok(true));
        assert_eq!(receiver.highest_contiguous(), Some(0));
        assert_eq!(receiver.apply(1), Ok(true));
        assert_eq!(receiver.highest_contiguous(), Some(2));
        assert_eq!(receiver.apply(0), Ok(false));
    }

    #[test]
    fn stream_buffer_reorders_and_deduplicates_ranges() {
        let mut buffer = StreamReceiveBuffer::new(32).unwrap();
        assert_eq!(
            buffer.insert(5, b" world").unwrap(),
            StreamInsertResult {
                delivered: Vec::new(),
                duplicate: false
            }
        );
        assert_eq!(
            buffer.insert(0, b"hello").unwrap(),
            StreamInsertResult {
                delivered: b"hello world".to_vec(),
                duplicate: false
            }
        );
        assert_eq!(
            buffer.insert(0, b"hello").unwrap(),
            StreamInsertResult {
                delivered: Vec::new(),
                duplicate: true
            }
        );
    }

    #[test]
    fn stream_buffer_rejects_conflicting_overlap_and_excess() {
        let mut buffer = StreamReceiveBuffer::new(4).unwrap();
        buffer.insert(4, b"abcd").unwrap();
        assert!(matches!(
            buffer.insert(5, b"x"),
            Err(ReliabilityError::ConflictingOverlap { offset: 5 })
        ));
        let mut bounded = StreamReceiveBuffer::new(2).unwrap();
        assert!(matches!(
            bounded.insert(4, b"abc"),
            Err(ReliabilityError::QueueFull { capacity: 2 })
        ));
    }

    #[test]
    fn overlapping_frame_fills_multiple_missing_ranges_without_losing_bytes() {
        let mut buffer = StreamReceiveBuffer::new(10).unwrap();
        assert!(buffer.insert(2, b"cd").unwrap().delivered.is_empty());
        assert!(buffer.insert(6, b"gh").unwrap().delivered.is_empty());
        assert_eq!(
            buffer.missing_ranges(0, b"abcdefghij").unwrap(),
            vec![(0, 2), (4, 6), (8, 10)]
        );
        let result = buffer.insert(0, b"abcdefghij").unwrap();
        assert!(result.duplicate);
        assert_eq!(result.delivered, b"abcdefghij");
        assert_eq!(buffer.buffered_bytes(), 0);
        assert_eq!(buffer.next_offset(), 10);
    }

    #[test]
    fn duplicate_ranges_need_no_capacity_and_conflicts_preserve_state() {
        let mut buffer = StreamReceiveBuffer::new(4).unwrap();
        buffer.insert(4, b"abcd").unwrap();
        assert!(buffer.missing_ranges(4, b"abcd").unwrap().is_empty());
        assert!(buffer.insert(4, b"abcd").unwrap().duplicate);
        assert_eq!(buffer.buffered_bytes(), 4);
        assert!(matches!(
            buffer.insert(4, b"abcx"),
            Err(ReliabilityError::ConflictingOverlap { offset: 7 })
        ));
        assert_eq!(buffer.buffered_bytes(), 4);
    }
}
