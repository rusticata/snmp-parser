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

use der_parser::ber::*;
use der_parser::error::*;
use nom::combinator::{map, map_res};
use nom::{Err, IResult};

use crate::error::SnmpError;
use crate::snmp::{parse_ber_octetstring_as_slice, parse_snmp_v2c_pdu, SnmpPdu};
pub use crate::usm::{parse_usm_security_parameters, UsmSecurityParameters};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SecurityModel(pub u32);

#[allow(non_upper_case_globals)]
impl SecurityModel {
    pub const SnmpV1: SecurityModel = SecurityModel(1);
    pub const SnmpV2c: SecurityModel = SecurityModel(2);
    pub const USM: SecurityModel = SecurityModel(3);
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

#[derive(Debug, PartialEq)]
pub enum SecurityParameters<'a> {
    Raw(&'a [u8]),
    USM(UsmSecurityParameters<'a>),
}

/// An SNMPv3 message
#[derive(Debug, PartialEq)]
pub struct SnmpV3Message<'a> {
    /// Version, as raw-encoded: 3 for SNMPv3
    pub version: u32,
    pub header_data: HeaderData,
    pub security_params: SecurityParameters<'a>,
    pub data: ScopedPduData<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HeaderData {
    pub msg_id: u32,
    pub msg_max_size: u32,
    pub msg_flags: u8,
    pub msg_security_model: SecurityModel,
}

impl HeaderData {
    pub fn is_authenticated(&self) -> bool {
        self.msg_flags & 0b001 != 0
    }

    pub fn is_encrypted(&self) -> bool {
        self.msg_flags & 0b010 != 0
    }

    pub fn is_reportable(&self) -> bool {
        self.msg_flags & 0b100 != 0
    }
}

#[derive(Debug, PartialEq)]
pub enum ScopedPduData<'a> {
    Plaintext(ScopedPdu<'a>),
    Encrypted(&'a [u8]),
}

#[derive(Debug, PartialEq)]
pub struct ScopedPdu<'a> {
    pub ctx_engine_id: &'a [u8],
    pub ctx_engine_name: &'a [u8],
    /// ANY -- e.g., PDUs as defined in [RFC3416](https://tools.ietf.org/html/rfc3416)
    pub data: SnmpPdu<'a>,
}

pub(crate) fn parse_snmp_v3_data<'a>(
    i: &'a [u8],
    hdr: &HeaderData,
) -> IResult<&'a [u8], ScopedPduData<'a>, BerError> {
    if hdr.is_encrypted() {
        map_res(parse_ber_octetstring, |x| {
            x.as_slice().map(ScopedPduData::Encrypted)
        })(i)
    } else {
        parse_snmp_v3_plaintext_pdu(i)
    }
}

pub(crate) fn parse_secp<'a>(
    x: &BerObject<'a>,
    hdr: &HeaderData,
) -> Result<SecurityParameters<'a>, BerError> {
    match x.as_slice() {
        Ok(i) => match hdr.msg_security_model {
            SecurityModel::USM => match parse_usm_security_parameters(i) {
                Ok((_, usm)) => Ok(SecurityParameters::USM(usm)),
                _ => Err(BerError::BerValueError),
            },
            _ => Ok(SecurityParameters::Raw(i)),
        },
        _ => Err(BerError::BerValueError),
    }
}

/// Parse an SNMPv3 top-level message
///
/// Example:
///
/// ```rust
/// use snmp_parser::{parse_snmp_v3,ScopedPduData,SecurityModel};
///
/// static SNMPV3_REQ: &[u8] = include_bytes!("../assets/snmpv3_req.bin");
///
/// # fn main() {
/// match parse_snmp_v3(&SNMPV3_REQ) {
///   Ok((_, ref r)) => {
///     assert!(r.version == 3);
///     assert!(r.header_data.msg_security_model == SecurityModel::USM);
///     match r.data {
///       ScopedPduData::Plaintext(ref _pdu) => { },
///       ScopedPduData::Encrypted(_) => (),
///     }
///   },
///   Err(e) => panic!("{}", e),
/// }
/// # }
/// ```
pub fn parse_snmp_v3(i: &[u8]) -> IResult<&[u8], SnmpV3Message, SnmpError> {
    parse_ber_sequence_defined_g(|i, _| {
        let (i, version) = parse_ber_u32(i)?;
        let (i, header_data) = parse_snmp_v3_headerdata(i)?;
        let (i, secp) = map_res(parse_ber_octetstring, |x| parse_secp(&x, &header_data))(i)?;
        let (i, data) = parse_snmp_v3_data(i, &header_data)?;
        let msg = SnmpV3Message {
            version,
            header_data,
            security_params: secp,
            data,
        };
        Ok((i, msg))
    })(i)
    .map_err(Err::convert)
}

pub(crate) fn parse_snmp_v3_headerdata(i: &[u8]) -> IResult<&[u8], HeaderData, BerError> {
    parse_ber_sequence_defined_g(|i, _| {
        let (i, msg_id) = parse_ber_u32(i)?;
        let (i, msg_max_size) = parse_ber_u32(i)?;
        let (i, msg_flags) = map_res(parse_ber_octetstring_as_slice, |s| {
            if s.len() == 1 {
                Ok(s[0])
            } else {
                Err(BerError::BerValueError)
            }
        })(i)?;
        let (i, msg_security_model) = map(parse_ber_u32, SecurityModel)(i)?;
        let hdr = HeaderData {
            msg_id,
            msg_max_size,
            msg_flags,
            msg_security_model,
        };
        Ok((i, hdr))
    })(i)
}

fn parse_snmp_v3_plaintext_pdu(i: &[u8]) -> IResult<&[u8], ScopedPduData, BerError> {
    parse_ber_sequence_defined_g(|i, _| {
        let (i, ctx_engine_id) = parse_ber_octetstring_as_slice(i)?;
        let (i, ctx_engine_name) = parse_ber_octetstring_as_slice(i)?;
        let (i, data) = parse_snmp_v2c_pdu(i)?;
        let pdu = ScopedPdu {
            ctx_engine_id,
            ctx_engine_name,
            data,
        };
        Ok((i, ScopedPduData::Plaintext(pdu)))
    })(i)
}
