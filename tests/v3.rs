#[macro_use]
extern crate pretty_assertions;

extern crate nom;
extern crate snmp_parser;

use snmp_parser::*;

static SNMPV3_REQ: &[u8] = include_bytes!("../assets/snmpv3_req.bin");

#[test]
fn test_snmp_v3_req() {
    let bytes = SNMPV3_REQ;
    let sp = SecurityParameters::USM(UsmSecurityParameters {
        msg_authoritative_engine_id: b"",
        msg_authoritative_engine_boots: 0,
        msg_authoritative_engine_time: 0,
        msg_user_name: String::from(""),
        msg_authentication_parameters: b"",
        msg_privacy_parameters: b"",
    });
    let cei = [
        0x80, 0x00, 0x1f, 0x88, 0x80, 0x59, 0xdc, 0x48, 0x61, 0x45, 0xa2, 0x63, 0x22,
    ];
    let data = SnmpPdu::Generic(SnmpGenericPdu {
        pdu_type: PduType::GetRequest,
        req_id: 2098071598,
        err: ErrorStatus::NoError,
        err_index: 0,
        var: vec![],
    });
    let expected = SnmpV3Message {
        version: 3,
        header_data: HeaderData {
            msg_id: 821490644,
            msg_max_size: 65507,
            msg_flags: 4,
            msg_security_model: SecurityModel::USM,
        },
        security_params: sp,
        data: ScopedPduData::Plaintext(ScopedPdu {
            ctx_engine_id: &cei,
            ctx_engine_name: b"",
            data,
        }),
    };
    let (rem, res) = parse_snmp_v3(bytes).expect("parsing failed");
    // eprintln!("{:?}", res);
    assert!(rem.is_empty());
    assert_eq!(res, expected);
}

#[test]
fn test_snmp_v3_req_encrypted() {
    let bytes = include_bytes!("../assets/snmpv3_req_encrypted.bin");
    let (rem, msg) = parse_snmp_v3(bytes).expect("parsing failed");
    // eprintln!("{:?}", res);
    assert!(rem.is_empty());
    assert_eq!(msg.version, 3);
    assert_eq!(msg.header_data.msg_security_model, SecurityModel::USM);
}

#[test]
fn test_snmp_v3_report() {
    let bytes = include_bytes!("../assets/snmpv3-report.bin");
    let (rem, msg) = parse_snmp_v3(bytes).expect("parsing failed");
    // eprintln!("{:?}", res);
    assert!(rem.is_empty());
    assert_eq!(msg.version, 3);
    assert_eq!(msg.header_data.msg_security_model, SecurityModel::USM);
}

#[test]
fn test_snmp_v3_generic() {
    let bytes = SNMPV3_REQ;
    let res = parse_snmp_generic_message(bytes);
    // eprintln!("{:?}", res);
    let (rem, m) = res.expect("parse_snmp_generic_message");
    assert!(rem.is_empty());
    if let SnmpGenericMessage::V3(msg) = m {
        assert_eq!(msg.version, 3);
        assert_eq!(msg.header_data.msg_security_model, SecurityModel::USM);
    } else {
        panic!("unexpected PDU type");
    }
}
