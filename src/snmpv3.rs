//! SNMPv3 Parser
//!
//! SNMPv3 is defined in the following RFCs:
//!   - [RFC2570](https://tools.ietf.org/html/rfc2570): Introduction to SNMP v3
//!   - [RFC3412](https://tools.ietf.org/html/rfc3412): Message Processing and Dispatching for the
//!     Simple Network Management Protocol (SNMP)
//!
//! See also:
//!   - [RFC2578](https://tools.ietf.org/html/rfc2578): Structure of Management Information Version 2 (SMIv2)

use std::fmt;

use der_parser::*;
use nom::IResult;

use snmp::{SnmpPdu,parse_snmp_v1_pdu};

use error::SnmpError;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SecurityModel(pub u32);

#[allow(non_upper_case_globals)]
impl SecurityModel {
    pub const SnmpV1    : SecurityModel = SecurityModel(1);
    pub const SnmpV2c   : SecurityModel = SecurityModel(2);
    pub const USM       : SecurityModel = SecurityModel(3);
}

impl fmt::Debug for SecurityModel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
           1 => f.write_str("SnmpV1"),
           2 => f.write_str("SnmpV2c"),
           3 => f.write_str("USM"),
           n => f.debug_tuple("SecurityModel").field(&n).finish(),
        }
    }
}

#[derive(Debug,PartialEq)]
pub struct SnmpV3Message<'a> {
    pub version: u32,
    pub header_data: HeaderData,
    pub security_params: &'a[u8],
    pub data: ScopedPduData<'a>,
    // pub data: DerObject<'a>,
}

#[derive(Debug,PartialEq)]
pub struct HeaderData {
    pub msg_id: u32,
    pub msg_max_size: u32,
    pub msg_flags: u8,
    pub msg_security_model: SecurityModel,
}

impl HeaderData {
    pub fn is_authenticated(&self) -> bool { self.msg_flags & 0b001 != 0 }

    pub fn is_encrypted(&self) -> bool { self.msg_flags & 0b010 != 0 }

    pub fn is_reportable(&self) -> bool { self.msg_flags & 0b100 != 0 }
}

#[derive(Debug,PartialEq)]
pub enum ScopedPduData<'a> {
    Plaintext(ScopedPdu<'a>),
    Encrypted(&'a[u8]),
}

#[derive(Debug,PartialEq)]
pub struct ScopedPdu<'a> {
    pub ctx_engine_id: &'a[u8],
    pub ctx_engine_name: &'a[u8],
    /// ANY -- e.g., PDUs as defined in [RFC3416](https://tools.ietf.org/html/rfc3416)
    pub data: SnmpPdu<'a>,
}




fn parse_snmp_v3_data<'a>(i:&'a[u8], hdr: &HeaderData) -> IResult<&'a[u8],ScopedPduData<'a>> {
    if hdr.is_encrypted()
    {
        map_res!(i,
                 parse_der_octetstring,
                 |x: DerObject<'a>| x.as_slice().map(|x| ScopedPduData::Encrypted(x))
        )
    } else {
        parse_snmp_v3_plaintext_pdu(i)
    }
}

pub fn parse_snmp_v3<'a>(i:&'a[u8]) -> IResult<&'a[u8],SnmpV3Message<'a>,SnmpError> {
    fix_error!(
        i,
        SnmpError,
        parse_der_struct!(
            TAG DerTag::Sequence,
            vers: map_res!(parse_der_integer, |x: DerObject| x.as_u32()) >>
            hdr:  parse_snmp_v3_headerdata >>
            secp: map_res!(parse_der_octetstring, |x: DerObject<'a>| x.as_slice()) >>
            data: apply!(parse_snmp_v3_data,&hdr) >>
            ({
                SnmpV3Message{
                    version: vers,
                    header_data: hdr,
                    security_params: secp,
                    data: data
                }
            })
        )
    ).map(|x| x.1)
}

fn parse_snmp_v3_headerdata<'a>(i:&'a[u8]) -> IResult<&'a[u8],HeaderData> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        id: map_res!(parse_der_integer, |x: DerObject| x.as_u32()) >>
        sz: map_res!(parse_der_integer, |x: DerObject| x.as_u32()) >>
        fl: map_res!(parse_der_octetstring, |x: DerObject| x.as_slice().and_then(|s|
            if s.len() == 1 { Ok(s[0]) } else { Err(DerError::DerValueError) })) >>
        sm: map_res!(parse_der_integer, |x: DerObject| x.as_u32()) >>
        (
            HeaderData{
                msg_id: id,
                msg_max_size: sz,
                msg_flags: fl,
                msg_security_model: SecurityModel(sm),
            }
        )
    ).map(|x| x.1)
}

fn parse_snmp_v3_plaintext_pdu<'a>(i:&'a[u8]) -> IResult<&'a[u8],ScopedPduData<'a>> {
    parse_der_struct!(
        i,
        ctx_eng_id: map_res!(parse_der_octetstring, |x: DerObject<'a>| x.as_slice()) >>
        ctx_name:   map_res!(parse_der_octetstring, |x: DerObject<'a>| x.as_slice()) >>
        data:       parse_snmp_v1_pdu >>
        (
            ScopedPduData::Plaintext(ScopedPdu{
                ctx_engine_id: ctx_eng_id,
                ctx_engine_name: ctx_name,
                data: data
            })
        )
    ).map(|x| x.1)
}
