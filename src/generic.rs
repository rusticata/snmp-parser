use crate::error::SnmpError;
use crate::snmp::*;
use crate::snmpv3::*;
use der_parser::ber::*;
use der_parser::error::*;
use nom::bytes::streaming::take;
use nom::combinator::map_res;
use nom::{Err, IResult};
use std::str;

#[derive(Debug, PartialEq)]
pub enum SnmpGenericMessage<'a> {
    V1(SnmpMessage<'a>),
    V2(SnmpMessage<'a>),
    V3(SnmpV3Message<'a>),
}

fn parse_snmp_v1_pdu_content(i: &[u8]) -> IResult<&[u8], SnmpMessage, BerError> {
    let (i, community) = map_res(parse_ber_octetstring_as_slice, str::from_utf8)(i)?;
    let (i, pdu) = parse_snmp_v1_pdu(i)?;
    let msg = SnmpMessage {
        version: 0,
        community: community.to_string(),
        pdu,
    };
    Ok((i, msg))
}

fn parse_snmp_v2c_pdu_content(i: &[u8]) -> IResult<&[u8], SnmpMessage, BerError> {
    let (i, community) = map_res(parse_ber_octetstring_as_slice, str::from_utf8)(i)?;
    let (i, pdu) = parse_snmp_v2c_pdu(i)?;
    let msg = SnmpMessage {
        version: 1,
        community: community.to_string(),
        pdu,
    };
    Ok((i, msg))
}

fn parse_snmp_v3_pdu_content(i: &[u8]) -> IResult<&[u8], SnmpV3Message, BerError> {
    let (i, hdr) = parse_snmp_v3_headerdata(i)?;
    let (i, secp) = map_res(parse_ber_octetstring, |x| parse_secp(&x, &hdr))(i)?;
    let (i, data) = parse_snmp_v3_data(i, &hdr)?;
    let msg = SnmpV3Message {
        version: 3,
        header_data: hdr,
        security_params: secp,
        data,
    };
    Ok((i, msg))
}

pub fn parse_snmp_generic_message<'a>(
    i: &'a [u8],
) -> IResult<&'a [u8], SnmpGenericMessage, SnmpError> {
    let (rem, hdr) = ber_read_element_header(i).or(Err(Err::Error(SnmpError::InvalidMessage)))?;
    if hdr.tag != BerTag::Sequence {
        return Err(Err::Error(SnmpError::InvalidMessage));
    }
    let len = hdr
        .len
        .primitive()
        .map_err(|_| SnmpError::BerError(BerError::InvalidLength))?;
    let (rem, data) = take(len)(rem)?;
    let (r, version) = parse_ber_u32(data).map_err(Err::convert)?;
    match version {
        0 => {
            let (rem, msg) = parse_snmp_v1_pdu_content(r).map_err(Err::convert)?;
            Ok((rem, SnmpGenericMessage::V1(msg)))
        }
        1 => {
            let (rem, msg) = parse_snmp_v2c_pdu_content(r).map_err(Err::convert)?;
            Ok((rem, SnmpGenericMessage::V2(msg)))
        }
        3 => {
            let (rem, msg) = parse_snmp_v3_pdu_content(r).map_err(Err::convert)?;
            Ok((rem, SnmpGenericMessage::V3(msg)))
        }
        _ => Err(Err::Error(SnmpError::InvalidVersion)),
    }
    .map(|(_, res)| (rem, res)) // adjust remaining bytes
}
