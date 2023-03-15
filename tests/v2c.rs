#[macro_use]
extern crate pretty_assertions;
extern crate nom;
extern crate snmp_parser;

use asn1_rs::Oid;
use snmp_parser::*;

static SNMPV2_GET: &[u8] = include_bytes!("../assets/snmpv2c-get-response.bin");

#[test]
fn test_snmp_v2_get() {
    let bytes = SNMPV2_GET;
    let expected = SnmpMessage {
        version: 1,
        community: String::from("public"),
        pdu: SnmpPdu::Generic(SnmpGenericPdu {
            pdu_type: PduType::Response,
            req_id: 97083662,
            err: ErrorStatus(0),
            err_index: 0,
            var: vec![
                SnmpVariable {
                    oid: Oid::from(&[1, 3, 6, 1, 2, 1, 25, 1, 1, 0]).unwrap(),
                    val: VarBindValue::Value(ObjectSyntax::TimeTicks(970069)),
                },
                SnmpVariable {
                    oid: Oid::from(&[1, 3, 6, 1, 2, 1, 25, 1, 5, 0]).unwrap(),
                    val: VarBindValue::Value(ObjectSyntax::Gauge32(3)),
                },
                SnmpVariable {
                    oid: Oid::from(&[1, 3, 6, 1, 2, 1, 25, 1, 5, 1]).unwrap(),
                    val: VarBindValue::NoSuchInstance,
                },
            ],
        }),
    };
    let (rem, r) = parse_snmp_v2c(bytes).expect("parsing failed");

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
