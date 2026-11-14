use netlink_packet_utils::{buffer, DecodeError};

buffer!(PacketBuffer(36) {
    opcode: (u8, 0),
    count: (u16, 1..3),
    sequence: (u32, 3..7),
    length: (u64, 7..15),
    signed_short: (i16, 15..17),
    signed_word: (i32, 17..21),
    signed_long: (i64, 21..29),
    payload: (slice, 29..36),
});

#[test]
fn generated_accessors_preserve_field_values_and_mutate_payload() {
    let mut bytes = [0_u8; 36];
    {
        let mut packet = PacketBuffer::new_checked(&mut bytes[..]).unwrap();
        packet.set_opcode(7);
        packet.set_count(0x1234);
        packet.set_sequence(0x1234_5678);
        packet.set_length(0x1234_5678_90ab_cdef);
        packet.set_signed_short(-1234);
        packet.set_signed_word(-123_456);
        packet.set_signed_long(-123_456_789);
        packet.payload_mut().copy_from_slice(b"payload");
    }

    let packet = PacketBuffer::new_checked(&bytes[..]).unwrap();
    assert_eq!(packet.opcode(), 7);
    assert_eq!(packet.count(), 0x1234);
    assert_eq!(packet.sequence(), 0x1234_5678);
    assert_eq!(packet.length(), 0x1234_5678_90ab_cdef);
    assert_eq!(packet.signed_short(), -1234);
    assert_eq!(packet.signed_word(), -123_456);
    assert_eq!(packet.signed_long(), -123_456_789);
    assert_eq!(packet.payload(), b"payload");
    assert_eq!(&bytes[1..3], &0x1234_u16.to_ne_bytes());
    assert_eq!(&bytes[3..7], &0x1234_5678_u32.to_ne_bytes());
    assert_eq!(&bytes[15..17], &(-1234_i16).to_ne_bytes());
}

#[test]
fn generated_checked_constructor_rejects_short_buffers() {
    for length in 0..36 {
        let bytes = vec![0_u8; length];
        assert!(PacketBuffer::new_checked(&bytes[..]).is_err());
    }
    assert!(PacketBuffer::new_checked(&[0_u8; 36][..]).is_ok());
}
