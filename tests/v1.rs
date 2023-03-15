#[macro_use]
extern crate hex_literal;
extern crate nom;
extern crate snmp_parser;

use asn1_rs::Oid;
use snmp_parser::*;
use std::net::Ipv4Addr;

const SNMPV1_RESPONSE: &[u8] = &hex!(
    "
30 82 00 59 02 01 00 04 06 70 75 62 6c 69 63 a2
82 00 4a 02 02 26 72 02 01 00 02 01 00 30 82 00
3c 30 82 00 10 06 0b 2b 06 01 02 01 19 03 02 01
05 01 02 01 03 30 82 00 10 06 0b 2b 06 01 02 01
19 03 05 01 01 01 02 01 03 30 82 00 10 06 0b 2b
06 01 02 01 19 03 05 01 02 01 04 01 a0
"
);

#[test]
fn test_snmp_v1_response() {
    let bytes: &[u8] = SNMPV1_RESPONSE;
    match parse_snmp_v1(bytes) {
        Ok((rem, pdu)) => {
            // println!("pdu: {:?}", pdu);
            assert!(rem.is_empty());
            assert_eq!(pdu.version, 0);
            assert_eq!(&pdu.community as &str, "public");
            assert_eq!(pdu.pdu_type(), PduType::Response);
        }
        e => panic!("Error: {:?}", e),
    }
}

static SNMPV1_REQ: &[u8] = include_bytes!("../assets/snmpv1_req.bin");

#[test]
fn test_snmp_v1_req() {
    let bytes = SNMPV1_REQ;
    let expected = SnmpMessage {
        version: 0,
        community: String::from("public"),
        pdu: SnmpPdu::Generic(SnmpGenericPdu {
            pdu_type: PduType::GetRequest,
            req_id: 38,
            err: ErrorStatus(0),
            err_index: 0,
            var: vec![SnmpVariable {
                oid: Oid::from(&[1, 3, 6, 1, 2, 1, 1, 2, 0]).unwrap(),
                val: VarBindValue::Unspecified,
            }],
        }),
    };
    let (rem, r) = parse_snmp_v1(bytes).expect("parsing failed");
    // debug!("r: {:?}",r);
    eprintln!(
        "SNMP: v={}, c={:?}, pdu_type={:?}",
        r.version,
        r.community,
        r.pdu_type()
    );
    // debug!("PDU: type={}, {:?}", pdu_type, pdu_res);
    for v in r.vars_iter() {
        eprintln!("v: {:?}", v);
    }
    assert!(rem.is_empty());
    assert_eq!(r, expected);
}

static SNMPV1_TRAP_COLDSTART: &[u8] = include_bytes!("../assets/snmpv1_trap_coldstart.bin");

#[test]
fn test_snmp_v1_trap_coldstart() {
    let bytes = SNMPV1_TRAP_COLDSTART;
    let (rem, pdu) = parse_snmp_v1(bytes).expect("parsing failed");
    // println!("pdu: {:?}", pdu);
    assert!(rem.is_empty());
    assert_eq!(pdu.version, 0);
    assert_eq!(&pdu.community as &str, "public");
    assert_eq!(pdu.pdu_type(), PduType::TrapV1);
    match pdu.pdu {
        SnmpPdu::TrapV1(trap) => {
            assert_eq!(
                trap.enterprise,
                Oid::from(&[1, 3, 6, 1, 4, 1, 4, 1, 2, 21]).unwrap()
            );
            assert_eq!(
                trap.agent_addr,
                NetworkAddress::IPv4(Ipv4Addr::new(127, 0, 0, 1))
            );
        }
        _ => panic!("unexpected pdu type"),
    }
}
