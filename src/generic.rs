use crate::error::SnmpError;
use crate::snmp::*;
use crate::snmpv3::*;
use der_parser::ber::*;
use nom::{Err, IResult};
use std::str;

#[derive(Debug, PartialEq)]
pub enum SnmpGenericMessage<'a> {
    V1(SnmpMessage<'a>),
    V2(SnmpMessage<'a>),
    V3(SnmpV3Message<'a>),
}

pub fn parse_snmp_generic_message<'a>(
    i: &'a [u8],
) -> IResult<&'a [u8], SnmpGenericMessage, SnmpError> {
    let (rem, hdr) = ber_read_element_header(i).or(Err(Err::Error(SnmpError::InvalidMessage)))?;
    if hdr.tag != BerTag::Sequence {
        return Err(Err::Error(SnmpError::InvalidMessage));
    }
    let (rem, data) = take!(rem, hdr.len as usize)?;
    let (r, version) = upgrade_error!(parse_ber_u32(data))?;
    match version {
        0 => upgrade_error!(do_parse! {
            r,
            community: map_res!(parse_ber_octetstring_as_slice, str::from_utf8) >>
            pdu:       parse_snmp_v1_pdu >>
            (
                SnmpGenericMessage::V1(SnmpMessage{
                    version,
                    community: community.to_string(),
                    pdu
                })
            )
        }),
        1 => upgrade_error!(do_parse! {
            r,
            community: map_res!(parse_ber_octetstring_as_slice, str::from_utf8) >>
            pdu:       parse_snmp_v2c_pdu >>
            (
                SnmpGenericMessage::V2(SnmpMessage{
                    version,
                    community: community.to_string(),
                    pdu
                })
            )
        }),
        3 => upgrade_error!(do_parse! {
            r,
            hdr:  parse_snmp_v3_headerdata >>
            secp: map_res!(parse_ber_octetstring, |x: BerObject<'a>| parse_secp(&x,&hdr)) >>
            data: call!(parse_snmp_v3_data, &hdr) >>
            (
                SnmpGenericMessage::V3(SnmpV3Message{
                    version,
                    header_data: hdr,
                    security_params: secp,
                    data
                })
            )
        }),
        _ => Err(Err::Error(SnmpError::InvalidVersion)),
    }
    .map(|(_, res)| (rem, res)) // adjust remaining bytes
}
