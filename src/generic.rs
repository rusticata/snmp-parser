use crate::error::SnmpError;
use crate::snmp::*;
use crate::snmpv3::*;
use asn1_rs::{Any, FromBer, Tag};
use nom::combinator::map_res;
use nom::{Err, IResult};

/// An SNMP messsage parser, accepting v1, v2c or v3 messages
///
/// # Examples
///
/// ```rust
/// use snmp_parser::{ScopedPduData, SecurityModel, SnmpGenericMessage};
/// use snmp_parser::asn1_rs::FromBer;
///
/// static SNMPV3_REQ: &[u8] = include_bytes!("../assets/snmpv3_req.bin");
///
/// match SnmpGenericMessage::from_ber(&SNMPV3_REQ) {
///   Ok((_, msg)) => {
///     match msg {
///       SnmpGenericMessage::V1(_) => todo!(),
///       SnmpGenericMessage::V2(_) => todo!(),
///       SnmpGenericMessage::V3(msgv3) => {
///         assert!(msgv3.version == 3);
///         assert!(msgv3.header_data.msg_security_model == SecurityModel::USM);
///         match msgv3.data {
///           ScopedPduData::Plaintext(_pdu) => { },
///           ScopedPduData::Encrypted(_) => (),
///         }
///       }
///     }
///   },
///   Err(e) => panic!("{}", e),
/// }
/// ```
#[derive(Debug, PartialEq)]
pub enum SnmpGenericMessage<'a> {
    /// SNMP Version 1 (SNMPv1) message
    V1(SnmpMessage<'a>),
    /// SNMP Version 2c (SNMPv2c) message
    V2(SnmpMessage<'a>),
    /// SNMP Version 3 (SNMPv3) message
    V3(SnmpV3Message<'a>),
}

impl<'a> FromBer<'a, SnmpError> for SnmpGenericMessage<'a> {
    fn from_ber(bytes: &'a [u8]) -> asn1_rs::ParseResult<'a, Self, SnmpError> {
        let (rem, any) = Any::from_ber(bytes).or(Err(Err::Error(SnmpError::InvalidMessage)))?;
        if any.tag() != Tag::Sequence {
            return Err(Err::Error(SnmpError::InvalidMessage));
        }
        let (r, version) = u32::from_ber(any.data).map_err(Err::convert)?;
        let (_, msg) = match version {
            0 => {
                let (rem, msg) = parse_snmp_v1_pdu_content(r)?;
                (rem, SnmpGenericMessage::V1(msg))
            }
            1 => {
                let (rem, msg) = parse_snmp_v2c_pdu_content(r)?;
                (rem, SnmpGenericMessage::V2(msg))
            }
            3 => {
                let (rem, msg) = parse_snmp_v3_pdu_content(r)?;
                (rem, SnmpGenericMessage::V3(msg))
            }
            _ => return Err(Err::Error(SnmpError::InvalidVersion)),
        };
        Ok((rem, msg))
    }
}

fn parse_snmp_v1_pdu_content(i: &[u8]) -> IResult<&[u8], SnmpMessage, SnmpError> {
    let (i, community) = parse_ber_octetstring_as_str(i).map_err(Err::convert)?;
    let (i, pdu) = parse_snmp_v1_pdu(i)?;
    let msg = SnmpMessage {
        version: 0,
        community: community.to_string(),
        pdu,
    };
    Ok((i, msg))
}

fn parse_snmp_v2c_pdu_content(i: &[u8]) -> IResult<&[u8], SnmpMessage, SnmpError> {
    let (i, community) = parse_ber_octetstring_as_str(i).map_err(Err::convert)?;
    let (i, pdu) = parse_snmp_v2c_pdu(i)?;
    let msg = SnmpMessage {
        version: 1,
        community: community.to_string(),
        pdu,
    };
    Ok((i, msg))
}

fn parse_snmp_v3_pdu_content(i: &[u8]) -> IResult<&[u8], SnmpV3Message, SnmpError> {
    let (i, hdr) = parse_snmp_v3_headerdata(i)?;
    let (i, secp) = map_res(<&[u8]>::from_ber, |x| parse_secp(x, &hdr))(i).map_err(Err::convert)?;
    let (i, data) = parse_snmp_v3_data(i, &hdr)?;
    let msg = SnmpV3Message {
        version: 3,
        header_data: hdr,
        security_params: secp,
        data,
    };
    Ok((i, msg))
}

/// Parse an SNMP messsage, accepting v1, v2c or v3 messages
///
/// This function is equivalent to `SnmpGenericMessage::from_ber`
pub fn parse_snmp_generic_message(i: &[u8]) -> IResult<&[u8], SnmpGenericMessage, SnmpError> {
    SnmpGenericMessage::from_ber(i)
}
