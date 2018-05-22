extern crate der_parser;
extern crate snmp_parser;
extern crate nom;

use std::net::Ipv4Addr;
use snmp_parser::*;
use der_parser::oid::Oid;

static SNMPV1_REQ: &'static [u8] = include_bytes!("../assets/snmpv1_req.bin");

#[test]
fn test_snmp_v1_req() {
    let empty = &b""[..];
    let bytes = SNMPV1_REQ;
    let expected = Ok((empty,SnmpMessage{
        version: 0,
        community: String::from("public"),
        pdu:SnmpPdu::Generic(
            SnmpGenericPdu{
                pdu_type: PduType::GetRequest,
                req_id:38,
                err:ErrorStatus(0),
                err_index:0,
                var:vec![
                    SnmpVariable{
                        oid: Oid::from(&[1, 3, 6, 1, 2, 1, 1, 2, 0]),
                        val: ObjectSyntax::Empty
                    }
                ],
            }),
    }));
    let res = parse_snmp_v1(&bytes);
    match &res {
        &Ok((_,ref r)) => {
            // debug!("r: {:?}",r);
            eprintln!("SNMP: v={}, c={:?}, pdu_type={:?}",r.version,r.community,r.pdu_type());
            // debug!("PDU: type={}, {:?}", pdu_type, pdu_res);
            for ref v in r.vars_iter() {
                eprintln!("v: {:?}",v);
            }
        },
        _ => (),
    };
    assert_eq!(res, expected);
}

static SNMPV1_TRAP_COLDSTART: &'static [u8] = include_bytes!("../assets/snmpv1_trap_coldstart.bin");

#[test]
fn test_snmp_v1_trap_coldstart() {
    let bytes = SNMPV1_TRAP_COLDSTART;
    match parse_snmp_v1(bytes) {
        Ok((rem,pdu)) => {
            // println!("pdu: {:?}", pdu);
            assert!(rem.is_empty());
            assert_eq!(pdu.version, 0);
            assert_eq!(&pdu.community as &str, "public");
            assert_eq!(pdu.pdu_type(), PduType::TrapV1);
            match pdu.pdu {
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
