//! SNMP Parser (v1 and v2c)
//!
//! SNMP is defined in the following RFCs:
//!   - [RFC1157](https://tools.ietf.org/html/rfc1157): SNMP v1
//!   - [RFC1442](https://tools.ietf.org/html/rfc1442): Structure of Management Information for version 2 of the Simple Network Management Protocol (SNMPv2)
//!   - [RFC1902](https://tools.ietf.org/html/rfc1902): SNMP v2 SMI
//!   - [RFC2578](https://tools.ietf.org/html/rfc2578): Structure of Management Information Version 2 (SMIv2)
//!   - [RFC3416](https://tools.ietf.org/html/rfc3416): SNMP v2
//!   - [RFC2570](https://tools.ietf.org/html/rfc2570): Introduction to SNMP v3

use crate::error::SnmpError;
use std::{fmt,str};
use std::net::Ipv4Addr;
use std::slice::Iter;
use nom::{Err, IResult};
use der_parser::ber::*;
use der_parser::error::*;
use der_parser::oid::Oid;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PduType(pub u32);

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
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum NetworkAddress {
    IPv4(Ipv4Addr),
}

/// This application-wide type represents a non-negative integer which
/// monotonically increases until it reaches a maximum value, when it
/// wraps around and starts increasing again from zero.  This memo
/// specifies a maximum value of 2^32-1 (4294967295 decimal) for
/// counters.
pub type Counter = u32;

/// This application-wide type represents a non-negative integer, which
/// may increase or decrease, but which latches at a maximum value.  This
/// memo specifies a maximum value of 2^32-1 (4294967295 decimal) for
/// gauges.
pub type Gauge = u32;

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
    pub pdu_type: PduType,
    pub req_id: u32,
    pub err: ErrorStatus,
    pub err_index: u32,
    pub var: Vec<SnmpVariable<'a>>,
}

#[derive(Debug,PartialEq)]
pub struct SnmpBulkPdu<'a> {
    pub req_id: u32,
    pub non_repeaters: u32,
    pub max_repetitions: u32,
    pub var: Vec<SnmpVariable<'a>>,
}

#[derive(Debug,PartialEq)]
pub struct SnmpTrapPdu<'a> {
    pub enterprise: Oid<'a>,
    pub agent_addr: NetworkAddress,
    pub generic_trap: TrapType,
    pub specific_trap: u32,
    pub timestamp: TimeTicks,
    pub var: Vec<SnmpVariable<'a>>,
}

#[derive(Debug,PartialEq)]
pub enum SnmpPdu<'a> {
    Generic(SnmpGenericPdu<'a>),
    Bulk(SnmpBulkPdu<'a>),
    TrapV1(SnmpTrapPdu<'a>),
}

/// An SNMPv1 or SNMPv2c message
#[derive(Debug,PartialEq)]
pub struct SnmpMessage<'a> {
    /// Version, as raw-encoded: 0 for SNMPv1, 1 for SNMPv2c
    pub version: u32,
    pub community: String,
    pub pdu: SnmpPdu<'a>,
}

impl<'a> SnmpGenericPdu<'a> {
    pub fn vars_iter(&'a self) -> Iter<SnmpVariable> {
        self.var.iter()
    }
}

impl<'a> SnmpTrapPdu<'a> {
    pub fn vars_iter(&'a self) -> Iter<SnmpVariable> {
        self.var.iter()
    }
}

impl<'a> SnmpPdu<'a> {
    pub fn pdu_type(&self) -> PduType {
        match *self {
            SnmpPdu::Generic(ref pdu) => pdu.pdu_type,
            SnmpPdu::Bulk(_)          => PduType::GetBulkRequest,
            SnmpPdu::TrapV1(_)        => PduType::TrapV1,
        }
    }

    pub fn vars_iter(&'a self) -> Iter<SnmpVariable> {
        match *self {
            SnmpPdu::Generic(ref pdu) => pdu.var.iter(),
            SnmpPdu::Bulk(ref pdu)    => pdu.var.iter(),
            SnmpPdu::TrapV1(ref pdu)  => pdu.var.iter(),
        }
    }
}

impl<'a> SnmpMessage<'a> {
    pub fn pdu_type(&self) -> PduType {
        self.pdu.pdu_type()
    }

    pub fn vars_iter(&'a self) -> Iter<SnmpVariable> {
        self.pdu.vars_iter()
    }
}

#[derive(Debug,PartialEq)]
pub struct SnmpVariable<'a> {
    pub oid: Oid<'a>,
    pub val: ObjectSyntax<'a>
}

#[derive(Debug,PartialEq)]
pub enum ObjectSyntax<'a> {
    Number(BerObject<'a>),
    String(&'a[u8]),
    Object(Oid<'a>),
    BitString(u8, BitStringObject<'a>),
    Empty,
    UnknownSimple(BerObject<'a>),
    IpAddress(NetworkAddress),
    Counter32(Counter),
    Gauge32(Gauge),
    TimeTicks(TimeTicks),
    Opaque(&'a[u8]),
    NsapAddress(&'a[u8]),
    Counter64(u64),
    UInteger32(u32),
    UnknownApplication(u32, &'a[u8]),
}

pub(crate) fn parse_ber_octetstring_as_slice(i:&[u8]) -> IResult<&[u8], &[u8], BerError> {
    match parse_ber_octetstring(i) {
        Ok((rem,ref obj)) => {
            match obj.content {
                BerObjectContent::OctetString(s) => {
                    Ok((rem, s))
                }
                _ => Err(Err::Error(BerError::InvalidTag)),
            }
        }
        Err(e) => Err(e)
    }
}

// Defined in RFC1442 and RFC2578
fn parse_objectsyntax<'a>(i:&'a[u8]) -> IResult<&'a[u8], ObjectSyntax, BerError> {
    match ber_read_element_header(i) {
        Ok((rem,hdr)) => {
            if hdr.is_application() {
                match hdr.tag.0 {
                    0 => {
                        map_res!(
                            rem,
                            call!(ber_read_element_content_as, BerTag::OctetString, hdr.len as usize, hdr.is_constructed(), 0),
                            |x:BerObjectContent| {
                                match x {
                                    BerObjectContent::OctetString(s) if s.len() == 4 => {
                                        Ok(ObjectSyntax::IpAddress(NetworkAddress::IPv4(Ipv4Addr::new(s[0],s[1],s[2],s[3]))))
                                    },
                                    _ => Err(BerError::InvalidTag),
                                }
                            }
                        )
                    },
                    1 ..= 3 => {
                        map_res!(
                            rem,
                            call!(ber_read_element_content_as, BerTag::Integer, hdr.len as usize, hdr.is_constructed(), 0),
                            |x:BerObjectContent| {
                                x.as_u32().map(|x| {
                                    match hdr.tag.0 {
                                        1 => ObjectSyntax::Counter32(x),
                                        2 => ObjectSyntax::Gauge32(x),
                                        3 => ObjectSyntax::TimeTicks(x),
                                        _ => unreachable!(),
                                    }
                                })
                            }
                        )
                    },
                    4 => {
                        map!(rem, take!(hdr.len as usize), ObjectSyntax::Opaque)
                    },
                    5 => {
                        map!(rem, take!(hdr.len as usize), ObjectSyntax::NsapAddress)
                    },
                    6 => {
                        map_res!(
                            rem,
                            call!(ber_read_element_content_as, BerTag::Integer, hdr.len as usize, hdr.is_constructed(), 0),
                            |x:BerObjectContent| {
                                x.as_u64().map(ObjectSyntax::Counter64)
                            }
                        )
                    },
                    7 => {
                        map_res!(
                            rem,
                            call!(ber_read_element_content_as, BerTag::Integer, hdr.len as usize, hdr.is_constructed(), 0),
                            |x:BerObjectContent| {
                                x.as_u32().map(ObjectSyntax::UInteger32)
                            }
                        )
                    },
                    _ => {
                        map!(rem, take!(hdr.len as usize), |x| ObjectSyntax::UnknownApplication(hdr.tag.0,x))
                    },
                }
            } else {
                        if hdr.len == 0 { return Ok((rem, ObjectSyntax::Empty)); }
                        map_res!(
                            rem,
                            call!(ber_read_element_content_as, hdr.tag, hdr.len as usize, hdr.is_constructed(), 0),
                            |x:BerObjectContent<'a>| {
                                match x {
                                    BerObjectContent::Integer(_)     => Ok(ObjectSyntax::Number(BerObject::from_obj(x))),
                                    BerObjectContent::OctetString(s) => Ok(ObjectSyntax::String(s)),
                                    BerObjectContent::OID(o)         => Ok(ObjectSyntax::Object(o)),
                                    BerObjectContent::BitString(a,s) => Ok(ObjectSyntax::BitString(a,s)),
                                    BerObjectContent::Null           => Ok(ObjectSyntax::Empty),
                                    _                                => Ok(ObjectSyntax::UnknownSimple(BerObject::from_obj(x))) as Result<_,u32>,
                                }
                            }
                        )
            }
        },
        Err(e)        => Err(e)
    }
}

#[inline]
fn parse_varbind<'a>(i:&'a [u8]) -> IResult<&'a [u8], SnmpVariable, BerError> {
    parse_der_struct!(
        i,
        TAG BerTag::Sequence,
        oid: map_res!(parse_ber_oid, |x:BerObject<'a>| x.as_oid_val()) >>
        val: parse_objectsyntax >>
             // eof!() >>
        (
            SnmpVariable{ oid, val }
        )
    ).map(|(rem,x)| (rem,x.1))
}

#[inline]
fn parse_varbind_list(i:&[u8]) -> IResult<&[u8], Vec<SnmpVariable>, BerError> {
    parse_der_struct!(
        i,
        TAG BerTag::Sequence,
        l: many0!(complete!(parse_varbind)) >>
           // eof!() >>
        ( l )
    ).map(|(rem,x)| (rem,x.1))
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
fn parse_networkaddress(i:&[u8]) -> IResult<&[u8], NetworkAddress, BerError> {
    match parse_ber(i) {
        Ok((rem,obj)) => {
            if obj.header.tag != BerTag::EndOfContent || obj.header.class != BerClass::Application {
                return Err(Err::Error(BerError::InvalidTag));
            }
            match obj.content {
                BerObjectContent::Unknown(_,s) if s.len() == 4 => {
                    Ok((rem, NetworkAddress::IPv4(Ipv4Addr::new(s[0],s[1],s[2],s[3]))))
                },
                _ => Err(Err::Error(BerError::InvalidTag)),
            }
        },
        Err(e)        => Err(e)
    }
}

/// <pre>
/// TimeTicks ::=
///     [APPLICATION 3]
///         IMPLICIT INTEGER (0..4294967295)
/// </pre>
fn parse_timeticks(i:&[u8]) -> IResult<&[u8], TimeTicks, BerError> {
    fn ber_read_integer_content(i:&[u8], _tag:BerTag, len: usize) -> IResult<&[u8], BerObjectContent, BerError> {
        ber_read_element_content_as(i, BerTag::Integer, len, false, 0)
    }
    map_res!(i, call!(parse_ber_implicit, BerTag(3), ber_read_integer_content), |x: BerObject| {
        match x.as_context_specific() {
            Ok((_,Some(x))) => x.as_u32(),
            _               => Err(BerError::BerTypeError),
        }
    })
}




fn parse_snmp_v1_generic_pdu(pdu: &[u8], tag:PduType) -> IResult<&[u8], SnmpPdu, BerError> {
    do_parse! {
        pdu,
        req_id:       parse_ber_u32 >>
        err:          parse_ber_u32 >>
        err_index:    parse_ber_u32 >>
        var_bindings: parse_varbind_list >>
        (
            SnmpPdu::Generic(
                SnmpGenericPdu {
                    pdu_type:  tag,
                    req_id,
                    err:       ErrorStatus(err),
                    err_index,
                    var:       var_bindings
                }
            )
        )
    }
}

fn parse_snmp_v1_bulk_pdu(pdu: &[u8]) -> IResult<&[u8], SnmpPdu, BerError> {
    do_parse! {
        pdu,
        req_id:          parse_ber_u32 >>
        non_repeaters:   parse_ber_u32 >>
        max_repetitions: parse_ber_u32 >>
        var_bindings:    parse_varbind_list >>
        (
            SnmpPdu::Bulk(
                SnmpBulkPdu {
                    req_id,
                    non_repeaters,
                    max_repetitions,
                    var:       var_bindings
                }
            )
        )
    }
}

fn parse_snmp_v1_trap_pdu<'a>(pdu: &'a [u8]) -> IResult<&'a [u8], SnmpPdu, BerError> {
    do_parse! {
        pdu,
        enterprise:    map_res!(parse_ber_oid, |x: BerObject<'a>| x.as_oid_val()) >>
        agent_addr:    parse_networkaddress >>
        generic_trap:  parse_ber_u32 >>
        specific_trap: parse_ber_u32 >>
        timestamp:     parse_timeticks >>
        var:           parse_varbind_list >>
        (
            SnmpPdu::TrapV1(
                SnmpTrapPdu {
                    enterprise,
                    agent_addr,
                    generic_trap:  TrapType(generic_trap as u8),
                    specific_trap,
                    timestamp,
                    var,
                }
            )
        )
    }
}

/// Parse a SNMP v1 message.
///
/// Top-level message
///
/// <pre>
/// Message ::=
///         SEQUENCE {
///             version          -- version-1 for this RFC
///                 INTEGER {
///                     version-1(0)
///                 },
///
///             community        -- community name
///                 OCTET STRING,
///
///             data             -- e.g., PDUs if trivial
///                 ANY          -- authentication is being used
///         }
/// </pre>
///
/// Example:
///
/// ```rust
/// # extern crate nom;
/// # #[macro_use] extern crate snmp_parser;
/// use snmp_parser::parse_snmp_v1;
///
/// static SNMPV1_REQ: &'static [u8] = include_bytes!("../assets/snmpv1_req.bin");
///
/// # fn main() {
/// match parse_snmp_v1(&SNMPV1_REQ) {
///   Ok((_, ref r)) => {
///     assert!(r.version == 0);
///     assert!(r.community == String::from("public"));
///     assert!(r.vars_iter().count() == 1);
///   },
///   Err(e) => panic!(e),
/// }
/// # }
/// ```
pub fn parse_snmp_v1(i:&[u8]) -> IResult<&[u8], SnmpMessage, SnmpError> {
    upgrade_error! {
        parse_der_struct!(
            i,
            TAG BerTag::Sequence,
            version:   map_res!(parse_ber_integer, |o:BerObject| o.as_u32()) >>
                       custom_check!(version != 0, BerError::BerValueError) >>
            community: map_res!(
                parse_ber_octetstring_as_slice,
                |s| str::from_utf8(s)
            ) >>
            pdu:       parse_snmp_v1_pdu >>
            (
                SnmpMessage{
                    version,
                    community: community.to_string(),
                    pdu
                }
            )
        ).map(|(rem,x)| (rem,x.1))
    }
}

pub(crate) fn parse_snmp_v1_pdu(i:&[u8]) -> IResult<&[u8], SnmpPdu, BerError> {
    match ber_read_element_header(i) {
        Ok((rem,hdr)) => {
            match PduType(hdr.tag.0) {
                PduType::GetRequest |
                PduType::GetNextRequest |
                PduType::Response |
                PduType::SetRequest     => parse_snmp_v1_generic_pdu(rem, PduType(hdr.tag.0)),
                PduType::TrapV1         => parse_snmp_v1_trap_pdu(rem),
                _                       => Err(Err::Error(BerError::BerValueError)),
                // _                       => { return IResult::Error(error_code!(ErrorKind::Custom(SnmpError::InvalidPdu))); },
            }
        },
        Err(e)        => Err(e)
        // IResult::Incomplete(i) => IResult::Incomplete(i),
        // IResult::Error(_)      => IResult::Error(error_code!(ErrorKind::Custom(129))),
        // // IResult::Error(_)      => IResult::Error(error_code!(ErrorKind::Custom(SnmpError::InvalidScopedPduData))),
    }
}

/// Parse a SNMP v2c message.
///
/// Top-level message
///
/// <pre>
/// Message ::=
///         SEQUENCE {
///             version
///                 INTEGER {
///                     version(1)  -- modified from RFC 1157
///                 },
///
///             community           -- community name
///                 OCTET STRING,
///
///             data                -- PDUs as defined in [4]
///                 ANY
///         }
/// </pre>
pub fn parse_snmp_v2c(i:&[u8]) -> IResult<&[u8], SnmpMessage, SnmpError> {
    upgrade_error! {
        parse_der_struct!(
            i,
            TAG BerTag::Sequence,
            version:   parse_ber_u32 >>
                       custom_check!(version != 1, BerError::BerValueError) >>
            community: map_res!(
                parse_ber_octetstring_as_slice,
                |s| str::from_utf8(s)
            ) >>
            pdu:       parse_snmp_v2c_pdu >>
            (
                SnmpMessage{
                    version,
                    community: community.to_string(),
                    pdu
                }
            )
        ).map(|(rem,x)| (rem,x.1))
    }
}

pub(crate) fn parse_snmp_v2c_pdu(i:&[u8]) -> IResult<&[u8], SnmpPdu, BerError> {
    match ber_read_element_header(i) {
        Ok((rem,hdr)) => {
            match PduType(hdr.tag.0) {
                PduType::GetRequest |
                PduType::GetNextRequest |
                PduType::Response |
                PduType::SetRequest |
                PduType::InformRequest |
                PduType::TrapV2 |
                PduType::Report         => parse_snmp_v1_generic_pdu(rem, PduType(hdr.tag.0)),
                PduType::GetBulkRequest => parse_snmp_v1_bulk_pdu(rem),
                PduType::TrapV1         => parse_snmp_v1_trap_pdu(rem),
                _                       => Err(Err::Error(BerError::BerValueError)),
                // _                       => { return IResult::Error(error_code!(ErrorKind::Custom(SnmpError::InvalidPdu))); },
            }
        },
        Err(e)        => Err(e)
        // IResult::Incomplete(i) => IResult::Incomplete(i),
        // IResult::Error(_)      => IResult::Error(error_code!(ErrorKind::Custom(129))),
        // // IResult::Error(_)      => IResult::Error(error_code!(ErrorKind::Custom(SnmpError::InvalidScopedPduData))),
    }
}
