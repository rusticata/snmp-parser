extern crate der_parser;
extern crate snmp_parser;
extern crate nom;

use std::net::Ipv4Addr;
use nom::IResult;
use snmp_parser::{NetworkAddress,PduType,SnmpPdu,parse_snmp_v1};
use der_parser::oid::Oid;

static SNMPV1_TRAP_COLDSTART: &'static [u8] = include_bytes!("../assets/snmpv1_trap_coldstart.bin");

#[test]
fn test_snmp_v1_trap_coldstart() {
    let bytes = SNMPV1_TRAP_COLDSTART;
    match parse_snmp_v1(bytes) {
        IResult::Done(rem,pdu) => {
            // println!("pdu: {:?}", pdu);
            assert!(rem.is_empty());
            assert_eq!(pdu.version, 0);
            assert_eq!(pdu.community, b"public");
            assert_eq!(pdu.pdu_type, PduType::TrapV1);
            match pdu.parsed_pdu {
                SnmpPdu::TrapV1(trap) => {
                    assert_eq!(trap.enterprise, Oid::from(&[1, 3, 6, 1, 4, 1, 4, 1, 2, 21]));
                    assert_eq!(trap.agent_addr, NetworkAddress::IPv4(Ipv4Addr::new(127,0,0,1)));
                }
                _                     => assert!(false),
            }
        },
        e => { eprintln!("Error: {:?}",e); assert!(false);}
    }
}
