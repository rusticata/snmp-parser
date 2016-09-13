use std::str;
use nom::{IResult,ErrorKind,Err};
use tls_parser::der::*;

#[derive(Debug,PartialEq)]
pub struct SnmpMessage<'a> {
    pub version: u32,
    pub community: &'a[u8],
    pub pdu_type: u8,
    pub pdu: &'a[u8],
}

impl<'a> SnmpMessage<'a> {
    pub fn get_community(self: &SnmpMessage<'a>) -> &'a str {
        str::from_utf8(self.community).unwrap()
    }
}


// named!(pub parse_snmp_v1<SnmpMessage>,
//    chain!(
//        der: parse_der,
//        || {
//            match der {
//                DerObject::Sequence(ref v) => {
//                    if v.len() != 3 { panic!("boo"); };
//                    // // XXX following lines fail with error:
//                    // // XXX error: slice pattern syntax is experimental (see issue #23121)
//                    // match v.as_slice() {
//                    //     [DerObject::Integer(i), DerObject::OctetString(s), _] => (i,s),
//                    //     _ => panic!("boo"),
//                    // }
//                    let vers = match v[0] {
//                        DerObject::Integer(i) => i as u32,
//                        _ => panic!("boo"),
//                    };
//                    let community = match v[1] {
//                        DerObject::OctetString(s) => s,
//                        _ => panic!("boo"),
//                    };
//                    println!("SNMP: v={}, c={:?}",vers,str::from_utf8(community).unwrap());
//                    SnmpMessage {
//                        version:vers,
//                        community:community,
//                    }
//                },
//                _ => panic!("boo"),
//            }
//    })
// );

pub fn parse_snmp_v1<'a>(i:&'a[u8]) -> IResult<&'a[u8],SnmpMessage<'a>> {
    let der = parse_der(i);
    match der {
        IResult::Done(i,DerObject::Sequence(ref v)) => {
            if v.len() != 3 { return IResult::Error(Err::Code(ErrorKind::Custom(128))); };
            // // XXX following lines fail with error:
            // // XXX error: slice pattern syntax is experimental (see issue #23121)
            // match v.as_slice() {
            //     [DerObject::Integer(i), DerObject::OctetString(s), _] => (i,s),
            //     _ => panic!("boo"),
            // }
            let vers = match v[0] {
                DerObject::Integer(i) => i as u32,
                _ => { return IResult::Error(Err::Code(ErrorKind::Custom(128))); },
            };
            let community = match v[1] {
                DerObject::OctetString(s) => s,
                _ => { return IResult::Error(Err::Code(ErrorKind::Custom(128))); },
            };
            let (pdu_type,pdu) = match v[2] {
                DerObject::ContextSpecific(tag,c) => (tag,c),
                _ => { return IResult::Error(Err::Code(ErrorKind::Custom(128))); },
            };
            // XXX PDU type is inside the context-specific field !
            let test = chain!(pdu,
                req_id: parse_der ~
                err: parse_der ~
                err_index: parse_der ~
                var_bindings: parse_der,
                || {
                    println!("req_id: {:?}",req_id);
                    println!("err: {:?}",err);
                    println!("err_index: {:?}",err_index);
                    println!("var_bindings: {:?}",var_bindings);
                    ()
                });
            println!("chain: {:?}",test);
            println!("SNMP: v={}, c={:?}",vers,str::from_utf8(community).unwrap());
            println!("PDU: type={}, {:?}", pdu_type, v[2]);
            //println!("res_pdu_type: {:?}", res_pdu_type);
            IResult::Done(i,
                SnmpMessage {
                    version:vers,
                    community:community,
                    pdu_type:pdu_type,
                    pdu:pdu,
                }
            )
        },
        _ => { return IResult::Error(Err::Code(ErrorKind::Custom(128))); },
    }
}

#[cfg(test)]
mod tests {
    use snmp::*;
    use nom::{IResult,Needed};

static SNMPV1_REQ: &'static [u8] = &[
    0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
    0x63, 0xa0, 0x19, 0x02, 0x01, 0x26, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
    0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
    0x02, 0x00, 0x05, 0x00
];

#[test]
fn test_snmp_v1_req() {
    let bytes = SNMPV1_REQ;
    let expected = IResult::Incomplete(Needed::Size(260));
    let res = parse_snmp_v1(&bytes);
    assert_eq!(res, expected);
}


}
