use snmp_parser::{parse_snmp_generic_message, ScopedPduData, SnmpGenericMessage, SnmpPdu};

fn v1_or_v2_request(version: u8, pdu_tag: u8) -> Vec<u8> {
    // SEQUENCE { version, community "public", PDU { request-id -1, 0, 0, {} } }
    let message = vec![
        0x30, 0x18, 0x02, 0x01, version, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', pdu_tag,
        0x0b, 0x02, 0x01, 0xff, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
    ];
    // The outer content is 24 bytes.
    assert_eq!(message.len(), 26);
    message
}

#[test]
fn negative_request_id_in_v1_and_v2_get() {
    for (version, pdu_tag) in [(0, 0xa0), (1, 0xa0), (1, 0xa2)] {
        let message = v1_or_v2_request(version, pdu_tag);
        let (rem, parsed) = parse_snmp_generic_message(&message).unwrap();
        assert!(rem.is_empty());
        let pdu = match parsed {
            SnmpGenericMessage::V1(msg) | SnmpGenericMessage::V2(msg) => msg.pdu,
            SnmpGenericMessage::V3(_) => panic!("unexpected SNMP version"),
        };
        match pdu {
            SnmpPdu::Generic(pdu) => assert_eq!(pdu.req_id, -1),
            _ => panic!("unexpected PDU type"),
        }
    }
}

#[test]
fn negative_request_id_in_v2_bulk() {
    let message = v1_or_v2_request(1, 0xa5);
    let (rem, parsed) = parse_snmp_generic_message(&message).unwrap();
    assert!(rem.is_empty());
    match parsed {
        SnmpGenericMessage::V2(msg) => match msg.pdu {
            SnmpPdu::Bulk(pdu) => assert_eq!(pdu.req_id, -1),
            _ => panic!("unexpected PDU type"),
        },
        _ => panic!("unexpected SNMP version"),
    }
}

#[test]
fn negative_request_id_in_v3_plaintext() {
    let mut message = include_bytes!("../assets/snmpv3_req.bin").to_vec();
    // Change the first value byte of the four-byte request-id to make it negative.
    assert_eq!(&message[0x3f..0x42], &[0x02, 0x04, 0x7d]);
    message[0x41] = 0xfd;

    let (rem, parsed) = parse_snmp_generic_message(&message).unwrap();
    assert!(rem.is_empty());
    match parsed {
        SnmpGenericMessage::V3(msg) => match msg.data {
            ScopedPduData::Plaintext(scoped) => match scoped.data {
                SnmpPdu::Generic(pdu) => {
                    assert_eq!(pdu.req_id, i32::from_be_bytes([0xfd, 0x0e, 0x08, 0x2e]));
                }
                _ => panic!("unexpected PDU type"),
            },
            ScopedPduData::Encrypted(_) => panic!("unexpected encrypted PDU"),
        },
        _ => panic!("unexpected SNMP version"),
    }
}
