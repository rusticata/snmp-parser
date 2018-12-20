#[macro_use] extern crate pretty_assertions;
extern crate der_parser;
extern crate snmp_parser;
extern crate nom;

use nom::IResult;
use snmp_parser::*;
use der_parser::oid::Oid;

static SNMPV2_GET: &'static [u8] = include_bytes!("../assets/snmpv2c-get-response.bin");

#[test]
fn test_snmp_v2_get() {
    let empty = &b""[..];
    let bytes = SNMPV2_GET;
    let expected = Ok((empty,SnmpMessage{
        version: 1,
        community: String::from("public"),
        pdu:SnmpPdu::Generic(
            SnmpGenericPdu{
                pdu_type: PduType::Response,
                req_id:97083662,
                err:ErrorStatus(0),
                err_index:0,
                var:vec![
                    SnmpVariable{
                        oid: Oid::from(&[1, 3, 6, 1, 2, 1, 25, 1, 1, 0]),
                        val: ObjectSyntax::Ticks(970069)
                    },
                    SnmpVariable{
                        oid: Oid::from(&[1, 3, 6, 1, 2, 1, 25, 1, 5, 0]),
                        val: ObjectSyntax::Gauge(3)
                    },
                    SnmpVariable{
                        oid: Oid::from(&[1, 3, 6, 1, 2, 1, 25, 1, 5, 1]),
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
