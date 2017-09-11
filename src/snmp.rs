//! SNMP Parser
//!
//! SNMP is defined in the following RFCs:
//!   - [RFC1157](https://tools.ietf.org/html/rfc1157): SNMP v1
//!   - [RFC1902](https://tools.ietf.org/html/rfc1902): SNMP v2 SMI
//!   - [RFC3416](https://tools.ietf.org/html/rfc3416): SNMP v2
//!   - [RFC2570](https://tools.ietf.org/html/rfc2570): Introduction to SNMP v3

use std::str;
use nom::{IResult,ErrorKind,Err};
use der_parser::*;

use enum_primitive::FromPrimitive;

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum PduType {
    GetRequest = 0,
    GetNextRequest = 1,
    Response = 2,
    SetRequest = 3,
    TrapV1 = 4, // Obsolete, was the old Trap-PDU in SNMPv1
    GetBulkRequest = 5,
    InformRequest = 6,
    TrapV2 = 7,
    Report = 8,
}
}

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum TrapType {
    ColdStart = 0,
    WarmStart = 1,
    LinkDown = 2,
    LinkUp = 3,
    AuthenticationFailure = 4,
    EgpNeighborLoss = 5,
    EnterpriseSpecific = 6,
}
}

#[derive(Debug,PartialEq)]
pub struct SnmpGenericPdu<'a> {
    pub req_id: u32,
    pub err: u32,
    pub err_index: u32,
    pub var: DerObject<'a>,
}

#[derive(Debug,PartialEq)]
pub struct SnmpTrapPdu<'a> {
    enterprise: DerObject<'a>,
    agent_addr: DerObject<'a>,  // NetworkAddress
    generic_trap: DerObject<'a>, // Integer
    specific_trap: DerObject<'a>, // Integer,
    timestamp: DerObject<'a>, // TimeTicks
    pub var: DerObject<'a>,
}

#[derive(Debug,PartialEq)]
pub enum SnmpPdu<'a> {
    Generic(SnmpGenericPdu<'a>),
    TrapV1(SnmpTrapPdu<'a>),
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

impl<'a> SnmpGenericPdu<'a> {
    pub fn vars_iter(&'a self) -> SnmpPduIterator<'a> {
        SnmpPduIterator{ it:self.var.ref_iter() }
    }
}

impl<'a> SnmpMessage<'a> {
    pub fn vars_iter(&'a self) -> SnmpPduIterator<'a> {
        let obj = match self.parsed_pdu {
            Some(SnmpPdu::Generic(ref pdu)) => &pdu.var,
            Some(SnmpPdu::TrapV1(ref pdu))    => &pdu.var,
            _ => panic!("Attempt to iterator on an empty Pdu"),
        };
        SnmpPduIterator{ it:obj.ref_iter() }
    }
}

#[derive(Debug,PartialEq)]
pub struct SnmpMessage<'a> {
    pub version: u32,
    pub community: &'a[u8],
    pub pdu_type: PduType,
    pub raw_pdu: &'a[u8],
    parsed_pdu: Option<SnmpPdu<'a>>,
}

impl<'a> SnmpMessage<'a> {
    pub fn get_community(self: &SnmpMessage<'a>) -> &'a str {
        str::from_utf8(self.community).unwrap()
    }
}




pub fn parse_snmp_v1_request_pdu<'a>(pdu: &'a [u8]) -> IResult<&'a[u8],SnmpPdu<'a>> {
    do_parse!(pdu,
              req_id:       parse_der_integer >>
              err:          parse_der_integer >>
              err_index:    parse_der_integer >>
              var_bindings: parse_der_sequence >>
              (
                  SnmpPdu::Generic(
                      SnmpGenericPdu {
                          req_id:    req_id.content.as_u32().unwrap(),
                          err:       err.content.as_u32().unwrap(),
                          err_index: err_index.content.as_u32().unwrap(),
                          var:       var_bindings
                      }
                  )
              ))
}

pub fn parse_snmp_v1_trap_pdu<'a>(pdu: &'a [u8]) -> IResult<&'a[u8],SnmpPdu<'a>> {
    do_parse!(pdu,
              enterprise:    parse_der_oid >>
              agent_addr:    parse_der >> // XXX NetworkAddress
              generic_trap:  parse_der_integer >>
              specific_trap: parse_der_integer >>
              timestamp:     parse_der >> // XXX TimeTicks
              var_bindings:  parse_der_sequence >>
              (
                  SnmpPdu::TrapV1(
                      SnmpTrapPdu {
                          enterprise:    enterprise,
                          agent_addr:    agent_addr,
                          generic_trap:  generic_trap,
                          specific_trap: specific_trap,
                          timestamp:     timestamp,
                          var:           var_bindings
                      }
                  )
              ))
}

/// Caller is responsible to provide a DerObject of type Sequence, containing
/// a sequence (Integer,OctetString,Unknown)
pub fn parse_snmp_v1_content<'a>(obj: DerObject<'a>) -> IResult<&'a[u8],SnmpMessage<'a>> {
    if let DerObjectContent::Sequence(ref v) = obj.content {
        if v.len() != 3 { return IResult::Error(Err::Code(ErrorKind::Custom(128))); };
        let vers = match v[0].content.as_u32() {
            Some (u) => u,
            None     => return IResult::Error(Err::Code(ErrorKind::Custom(129))),
        };
        let community = v[1].content.as_slice().unwrap();
        let pdu_type_int = v[2].tag;
        let pdu_type = match PduType::from_u8(pdu_type_int) {
            None => { return IResult::Error(Err::Code(ErrorKind::Custom(130))); },
            Some(t) => t,
        };
        let pdu = match v[2].content.as_slice() {
            Some(p) => p,
            None    => return IResult::Error(Err::Code(ErrorKind::Custom(131))),
        };
        let pdu_res = match pdu_type {
            PduType::GetRequest |
            PduType::GetNextRequest |
            PduType::Response |
            PduType::SetRequest => parse_snmp_v1_request_pdu(pdu),
            PduType::TrapV1     => parse_snmp_v1_trap_pdu(pdu),
            _                   => { return IResult::Error(Err::Code(ErrorKind::Custom(131))); },
        };
        match pdu_res {
            IResult::Done(rem,r) => {
                IResult::Done(rem,
                              SnmpMessage{
                                  version: vers,
                                  community: community,
                                  pdu_type: pdu_type,
                                  raw_pdu: pdu,
                                  parsed_pdu: Some(r),
                              }
                             )
            },
            _ => { return IResult::Error(Err::Code(ErrorKind::Custom(132))); },
        }
    } else {
        IResult::Error(Err::Code(ErrorKind::Custom(133)))
    }
}

pub fn parse_snmp_v1<'a>(i:&'a[u8]) -> IResult<&'a[u8],SnmpMessage<'a>> {
    flat_map!(
        i,
        parse_der_sequence_defined!(
            parse_der_integer,
            parse_der_octetstring,
            parse_der // XXX type is ANY
        ),
        parse_snmp_v1_content
    )
}

#[cfg(test)]
mod tests {
    use std::str;
    use snmp::*;
    use der_parser::*;
    use der_parser::oid::Oid;
    use nom::IResult;
    extern crate env_logger;

static SNMPV1_REQ: &'static [u8] = include_bytes!("../assets/snmpv1_req.bin");

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
        parsed_pdu:Some(SnmpPdu::Generic(
            SnmpGenericPdu{
                req_id:38,
                err:0,
                err_index:0,
                var:DerObject::from_obj(DerObjectContent::Sequence( vec![
                    DerObject::from_obj(
                        DerObjectContent::Sequence(vec![
                            DerObject::from_obj(DerObjectContent::OID(Oid::from(&[1, 3, 6, 1, 2, 1, 1, 2, 0]))),
                            DerObject::from_obj(DerObjectContent::Null)
                        ]),
                    ),
                ],)),
            })
        ),
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

static SNMPV1_TRAP_COLDSTART: &'static [u8] = include_bytes!("../assets/snmpv1_trap_coldstart.bin");

#[test]
fn test_snmp_v1_trap_coldstart() {
    let _ = env_logger::init();
    let empty = &b""[..];
    let bytes = SNMPV1_TRAP_COLDSTART;

    println!("{:?}", parse_snmp_v1(bytes));
}

}
