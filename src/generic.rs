use crate::error::SnmpError;
use crate::snmp::*;
use crate::snmpv3::*;
use asn1_rs::{Any, FromBer, Tag};
use nom::combinator::map_res;
use nom::{Err, IResult};

#[derive(Debug, PartialEq)]
pub enum SnmpGenericMessage<'a> {
    V1(SnmpMessage<'a>),
    V2(SnmpMessage<'a>),
    V3(SnmpV3Message<'a>),
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

pub fn parse_snmp_generic_message(i: &[u8]) -> IResult<&[u8], SnmpGenericMessage, SnmpError> {
    let (rem, any) = Any::from_ber(i).or(Err(Err::Error(SnmpError::InvalidMessage)))?;
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
