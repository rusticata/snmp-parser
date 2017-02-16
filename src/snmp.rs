use std::{mem,str};
use nom::{IResult,ErrorKind,Err};
use der_parser::der::*;

#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum PduType {
    GetRequest = 0,
    GetNextRequest = 1,
    Response = 2,
    SetRequest = 3,
    /// Obsolete, was the old Trap-PDU in SNMPv1
    TrapV1 = 4,
    GetBulkRequest = 5,
    InformRequest = 6,
    TrapV2 = 7,
    Report = 8,
}

impl PduType {
    pub fn from_u8(n: u8) -> Option<PduType> {
        if n <= 8 { Some(unsafe{ mem::transmute(n) }) }
        else { None }
    }
}

#[derive(Debug,Clone,PartialEq)]
pub struct RawSnmpPdu<'a> {
    pub req_id: u32,
    pub err: u32,
    pub err_index: u32,
//    pub var: &'a[u8],
//    pub req_id: DerObject<'a>,
//    pub err: DerObject<'a>,
//    pub err_index: DerObject<'a>,
    pub var: DerObject<'a>,
}

pub struct SnmpPduIterator<'a> {
    it: DerObjectRefIterator<'a>,
}

impl<'a> Iterator for SnmpPduIterator<'a> {
    type Item = &'a DerObject<'a>;
    fn next(&mut self) -> Option<&'a DerObject<'a>> {
        self.it.next()
    }
}

impl<'a> RawSnmpPdu<'a> {
    pub fn vars_iter(&'a self) -> SnmpPduIterator<'a> {
        SnmpPduIterator{ it:self.var.ref_iter() }
    }
}

impl<'a> SnmpMessage<'a> {
    pub fn vars_iter(&'a self) -> SnmpPduIterator<'a> {
        let obj = &self.parsed_pdu.as_ref().unwrap().var;
        SnmpPduIterator{ it:obj.ref_iter() }
    }
}

#[derive(Debug,PartialEq)]
pub struct SnmpMessage<'a> {
    pub version: u32,
    pub community: &'a[u8],
    pub pdu_type: PduType,
    pub raw_pdu: &'a[u8],
    parsed_pdu: Option<RawSnmpPdu<'a>>,
}

impl<'a> SnmpMessage<'a> {
    pub fn get_community(self: &SnmpMessage<'a>) -> &'a str {
        str::from_utf8(self.community).unwrap()
    }
}


// named!(pub parse_snmp_v1<SnmpMessage>,
//    do_parse!(
//        der: parse_der >>
//        (
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
//                    debug!("SNMP: v={}, c={:?}",vers,str::from_utf8(community).unwrap());
//                    SnmpMessage {
//                        version:vers,
//                        community:community,
//                    }
//                },
//                _ => panic!("boo"),
//            }
//    ))
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
            let (vers,community,(pdu_type_int,pdu)) =
                match (&v[0],&v[1],&v[2]) {
                    (&DerObject::Integer(i),&DerObject::OctetString(s),&DerObject::ContextSpecific(tag,c)) =>
                        (i as u32, s, (tag,c)),
                    _ => { return IResult::Error(Err::Code(ErrorKind::Custom(128))); },
                };
            let pdu_type = match PduType::from_u8(pdu_type_int) {
                None => { return IResult::Error(Err::Code(ErrorKind::Custom(128))); },
                Some(t) => t,
            };
            // XXX this is only valid for some PDU types
            let pdu_res = do_parse!(pdu,
                req_id:       parse_der_integer >>
                err:          parse_der_integer >>
                err_index:    parse_der_integer >>
                var_bindings: parse_der_sequence >>
                (
                    RawSnmpPdu {
                        req_id:req_id.as_u32().unwrap(),
                        err:err.as_u32().unwrap(),
                        err_index:err_index.as_u32().unwrap(),
                        var:var_bindings
                    }
                ));
            match pdu_res {
                IResult::Done(_,ref r) => {
                    IResult::Done(i,
                        SnmpMessage {
                            version:vers,
                            community:community,
                            pdu_type:pdu_type,
                            raw_pdu:pdu,
                            parsed_pdu:Some((*r).clone()),
                        }
                    )
                },
                _ => { return IResult::Error(Err::Code(ErrorKind::Custom(128))); },
            }
        },
        _ => { return IResult::Error(Err::Code(ErrorKind::Custom(128))); },
    }
}

#[cfg(test)]
mod tests {
    use std::str;
    use snmp::*;
    use der_parser::der::*;
    use nom::IResult;
    extern crate env_logger;

static SNMPV1_REQ: &'static [u8] = &[
    0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
    0x63, 0xa0, 0x19, 0x02, 0x01, 0x26, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
    0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
    0x02, 0x00, 0x05, 0x00
];

#[test]
fn test_snmp_v1_req() {
    let _ = env_logger::init();
    let empty = &b""[..];
    let bytes = SNMPV1_REQ;
    let expected = IResult::Done(empty,SnmpMessage{
        version: 0,
        community: b"public",
        pdu_type: PduType::GetRequest,
        raw_pdu: &SNMPV1_REQ[15..],
        parsed_pdu:Some(RawSnmpPdu{
            req_id:38,
            err:0,
            err_index:0,
            var:DerObject::Sequence( vec![
                    DerObject::Sequence(vec![DerObject::OID(vec![1, 3, 6, 1, 2, 1, 1, 2, 0]), DerObject::Null]),
            ],),
        }),
    });
    let res = parse_snmp_v1(&bytes);
    match &res {
        &IResult::Done(_,ref r) => {
            // debug!("r: {:?}",r);
            debug!("SNMP: v={}, c={:?}, pdu_type={:?}",r.version,r.get_community(),r.pdu_type);
            // debug!("PDU: type={}, {:?}", pdu_type, pdu_res);
            for ref v in r.vars_iter() {
                debug!("v: {:?}",v);
            }
        },
        _ => (),
    };
    assert_eq!(res, expected);
}


}
