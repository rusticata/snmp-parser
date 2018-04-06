//! SNMP Parser
//!
//! SNMP is defined in the following RFCs:
//!   - [RFC1157](https://tools.ietf.org/html/rfc1157): SNMP v1
//!   - [RFC1902](https://tools.ietf.org/html/rfc1902): SNMP v2 SMI
//!   - [RFC3416](https://tools.ietf.org/html/rfc3416): SNMP v2
//!   - [RFC2570](https://tools.ietf.org/html/rfc2570): Introduction to SNMP v3

use std::{fmt,str};
use std::net::Ipv4Addr;
use nom::{IResult,ErrorKind};
use der_parser::*;
use der_parser::oid::Oid;

use error::SnmpError;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PduType(pub u8);

#[allow(non_upper_case_globals)]
impl PduType {
    pub const GetRequest     : PduType = PduType(0);
    pub const GetNextRequest : PduType = PduType(1);
    pub const Response       : PduType = PduType(2);
    pub const SetRequest     : PduType = PduType(3);
    pub const TrapV1         : PduType = PduType(4); // Obsolete, was the old Trap-PDU in SNMPv1
    pub const GetBulkRequest : PduType = PduType(5);
    pub const InformRequest  : PduType = PduType(6);
    pub const TrapV2         : PduType = PduType(7);
    pub const Report         : PduType = PduType(8);
}

impl fmt::Debug for PduType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
           0 => f.write_str("GetRequest"),
           1 => f.write_str("GetNextRequest"),
           2 => f.write_str("Response"),
           3 => f.write_str("SetRequest"),
           4 => f.write_str("TrapV1"),
           5 => f.write_str("GetBulkRequest"),
           6 => f.write_str("InformRequest"),
           7 => f.write_str("TrapV2"),
           8 => f.write_str("Report"),
           n => f.debug_tuple("PduType").field(&n).finish(),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TrapType(pub u8);

impl TrapType {
    pub const COLD_START             : TrapType = TrapType(0);
    pub const WARM_START             : TrapType = TrapType(1);
    pub const LINK_DOWN              : TrapType = TrapType(2);
    pub const LINK_UP                : TrapType = TrapType(3);
    pub const AUTHENTICATION_FAILURE : TrapType = TrapType(4);
    pub const EGP_NEIGHBOR_LOSS      : TrapType = TrapType(5);
    pub const ENTERPRISE_SPECIFIC    : TrapType = TrapType(6);
}

impl fmt::Debug for TrapType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
           0 => f.write_str("coldStart"),
           1 => f.write_str("warmStart"),
           2 => f.write_str("linkDown"),
           3 => f.write_str("linkUp"),
           4 => f.write_str("authenticationFailure"),
           5 => f.write_str("egpNeighborLoss"),
           6 => f.write_str("enterpriseSpecific"),
           n => f.debug_tuple("TrapType").field(&n).finish(),
        }
    }
}

/// This CHOICE represents an address from one of possibly several
/// protocol families.  Currently, only one protocol family, the Internet
/// family, is present in this CHOICE.
#[derive(Debug, PartialEq)]
pub enum NetworkAddress {
    IPv4(Ipv4Addr),
}

/// This application-wide type represents a non-negative integer which
/// counts the time in hundredths of a second since some epoch.  When
/// object types are defined in the MIB which use this ASN.1 type, the
/// description of the object type identifies the reference epoch.
pub type TimeTicks = u32;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ErrorStatus(pub u32);

#[allow(non_upper_case_globals)]
impl ErrorStatus {
    pub const NoError    : ErrorStatus = ErrorStatus(0);
    pub const TooBig     : ErrorStatus = ErrorStatus(1);
    pub const NoSuchName : ErrorStatus = ErrorStatus(2);
    pub const BadValue   : ErrorStatus = ErrorStatus(3);
    pub const ReadOnly   : ErrorStatus = ErrorStatus(4);
    pub const GenErr     : ErrorStatus = ErrorStatus(5);
}

impl fmt::Debug for ErrorStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
           0 => f.write_str("NoError"),
           1 => f.write_str("TooBig"),
           2 => f.write_str("NoSuchName"),
           3 => f.write_str("BadValue"),
           4 => f.write_str("ReadOnly"),
           5 => f.write_str("GenErr"),
           n => f.debug_tuple("ErrorStatus").field(&n).finish(),
        }
    }
}

#[derive(Debug,PartialEq)]
pub struct SnmpGenericPdu<'a> {
    pub req_id: u32,
    pub err: ErrorStatus,
    pub err_index: u32,
    pub var: DerObject<'a>,
}

#[derive(Debug,PartialEq)]
pub struct SnmpTrapPdu<'a> {
    pub enterprise: Oid,
    pub agent_addr: NetworkAddress,
    pub generic_trap: TrapType,
    pub specific_trap: u32,
    pub timestamp: TimeTicks,
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
            SnmpPdu::Generic(ref pdu) => &pdu.var,
            SnmpPdu::TrapV1(ref pdu)  => &pdu.var,
        };
        SnmpPduIterator{ it:obj.ref_iter() }
    }
}

#[derive(Debug,PartialEq)]
pub struct SnmpMessage<'a> {
    pub version: u32,
    pub community: &'a[u8],
    pub pdu_type: PduType,
    pub parsed_pdu: SnmpPdu<'a>,
}

impl<'a> SnmpMessage<'a> {
    pub fn get_community(self: &SnmpMessage<'a>) -> &'a str {
        str::from_utf8(self.community).unwrap()
    }
}



#[inline]
fn parse_varbind(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_sequence_defined!(i,
                                parse_der_oid,
                                parse_der
                               )
}

#[inline]
fn parse_varbind_list(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_sequence_of!(i, parse_varbind)
}

/// <pre>
///  NetworkAddress ::=
///      CHOICE {
///          internet
///              IpAddress
///      }
/// IpAddress ::=
///     [APPLICATION 0]          -- in network-byte order
///         IMPLICIT OCTET STRING (SIZE (4))
/// </pre>
fn parse_networkaddress(i:&[u8]) -> IResult<&[u8],NetworkAddress> {
    match parse_der(i) {
        IResult::Done(rem,obj) => {
            if obj.tag != 0 || obj.class != 0b01 {
                return IResult::Error(error_code!(ErrorKind::Custom(DER_TAG_ERROR)));
            }
            match obj.content {
                DerObjectContent::Unknown(s) if s.len() == 4 => {
                    IResult::Done(rem, NetworkAddress::IPv4(Ipv4Addr::new(s[0],s[1],s[2],s[3])))
                },
                _ => IResult::Error(error_code!(ErrorKind::Custom(DER_TAG_ERROR))),
            }
        },
        IResult::Incomplete(i) => IResult::Incomplete(i),
        IResult::Error(e)      => IResult::Error(e),
    }
}

/// <pre>
/// TimeTicks ::=
///     [APPLICATION 3]
///         IMPLICIT INTEGER (0..4294967295)
/// </pre>
fn parse_timeticks(i:&[u8]) -> IResult<&[u8],TimeTicks> {
    fn der_read_integer_content(i:&[u8], _tag:u8, len: usize) -> IResult<&[u8],DerObjectContent,u32> {
        der_read_element_content_as(i, DerTag::Integer as u8, len)
    }
    map_res!(i, apply!(parse_der_implicit, 3, der_read_integer_content), |x: DerObject| {
        match x.as_context_specific() {
            Ok((_,Some(x))) => x.as_u32(),
            _               => Err(DerError::DerTypeError),
        }
    })
}




pub fn parse_snmp_v1_request_pdu<'a>(pdu: &'a [u8]) -> IResult<&'a[u8],SnmpPdu<'a>> {
    do_parse!(pdu,
              req_id:       map_res!(parse_der_integer,|x: DerObject| x.as_u32()) >>
              err:          map_res!(parse_der_integer,|x: DerObject| x.as_u32()) >>
              err_index:    map_res!(parse_der_integer,|x: DerObject| x.as_u32()) >>
                            error_if!(true == false, ErrorKind::Custom(128)) >>
              var_bindings: parse_varbind_list >>
              (
                  SnmpPdu::Generic(
                      SnmpGenericPdu {
                          req_id:    req_id,
                          err:       ErrorStatus(err),
                          err_index: err_index,
                          var:       var_bindings
                      }
                  )
              ))
}

pub fn parse_snmp_v1_trap_pdu<'a>(pdu: &'a [u8]) -> IResult<&'a[u8],SnmpPdu<'a>> {
    do_parse!(
        pdu,
        enterprise:    map_res!(parse_der_oid, |x: DerObject| x.as_oid_val()) >>
        agent_addr:    parse_networkaddress >>
        generic_trap:  map_res!(parse_der_integer, |x: DerObject| x.as_u32()) >>
        specific_trap: map_res!(parse_der_integer, |x: DerObject| x.as_u32()) >>
        timestamp:     parse_timeticks >>
        var_bindings:  parse_der_sequence >>
        (
            SnmpPdu::TrapV1(
                SnmpTrapPdu {
                    enterprise:    enterprise,
                    agent_addr:    agent_addr,
                    generic_trap:  TrapType(generic_trap as u8),
                    specific_trap: specific_trap,
                    timestamp:     timestamp,
                    var:           var_bindings
                }
            )
        )
    )
}

/// Caller is responsible to provide a DerObject of type implicit Sequence, containing
/// (Integer,OctetString,Unknown)
pub fn parse_snmp_v1_content<'a>(obj: DerObject<'a>) -> IResult<&'a[u8],SnmpMessage<'a>,SnmpError> {
    if let DerObjectContent::Sequence(ref v) = obj.content {
        if v.len() != 3 { return IResult::Error(error_code!(ErrorKind::Custom(SnmpError::InvalidMessage))); };
        let vers = match v[0].content.as_u32() {
            Ok (u) if u <= 2 => u,
            _  => return IResult::Error(error_code!(ErrorKind::Custom(SnmpError::InvalidVersion))),
        };
        let community = v[1].content.as_slice().unwrap();
        let pdu_type = PduType(v[2].tag);
        let pdu = match v[2].content.as_slice() {
            Ok(p) => p,
            _     => return IResult::Error(error_code!(ErrorKind::Custom(SnmpError::InvalidPdu))),
        };
        // v[2] is an implicit sequence: class 2 structured 1
        // tag is the pdu_type
        let pdu_res = match pdu_type {
            PduType::GetRequest |
            PduType::GetNextRequest |
            PduType::Response |
            PduType::SetRequest => parse_snmp_v1_request_pdu(pdu),
            PduType::TrapV1     => parse_snmp_v1_trap_pdu(pdu),
            _                   => { return IResult::Error(error_code!(ErrorKind::Custom(SnmpError::InvalidPdu))); },
        };
        match pdu_res {
            IResult::Done(rem,r) => {
                IResult::Done(rem,
                              SnmpMessage{
                                  version: vers,
                                  community: community,
                                  pdu_type: pdu_type,
                                  parsed_pdu: r,
                              }
                             )
            },
            _ => { return IResult::Error(error_code!(ErrorKind::Custom(SnmpError::InvalidPdu))); },
        }
    } else {
        IResult::Error(error_code!(ErrorKind::Custom(SnmpError::InvalidMessage)))
    }
}

pub fn parse_snmp_v1<'a>(i:&'a[u8]) -> IResult<&'a[u8],SnmpMessage<'a>,SnmpError> {
    flat_map!(
        i,
        fix_error!(SnmpError,
                   parse_der_sequence_defined!(
                       parse_der_integer,
                       parse_der_octetstring,
                       parse_der // XXX type is ANY
                       )),
        parse_snmp_v1_content
    )
}
