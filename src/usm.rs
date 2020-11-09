//! RFC2274 - User-based Security Model (USM) for version 3 of the Simple Network Management Protocol (SNMPv3)

use crate::snmp::parse_ber_octetstring_as_slice;
use der_parser::ber::*;
use der_parser::error::BerError;
use nom::combinator::map_res;
use nom::IResult;
use std::str;

#[derive(Debug, PartialEq)]
pub struct UsmSecurityParameters<'a> {
    pub msg_authoritative_engine_id: &'a [u8],
    pub msg_authoritative_engine_boots: u32,
    pub msg_authoritative_engine_time: u32,
    pub msg_user_name: String,
    pub msg_authentication_parameters: &'a [u8],
    pub msg_privacy_parameters: &'a [u8],
}

pub fn parse_usm_security_parameters(i: &[u8]) -> IResult<&[u8], UsmSecurityParameters, BerError> {
    parse_ber_sequence_defined_g(|_, i| {
        let (i, msg_authoritative_engine_id) = parse_ber_octetstring_as_slice(i)?;
        let (i, msg_authoritative_engine_boots) = parse_ber_u32(i)?;
        let (i, msg_authoritative_engine_time) = parse_ber_u32(i)?;
        let (i, msg_user_name) = map_res(parse_ber_octetstring_as_slice, str::from_utf8)(i)?;
        let (i, msg_authentication_parameters) = parse_ber_octetstring_as_slice(i)?;
        let (i, msg_privacy_parameters) = parse_ber_octetstring_as_slice(i)?;
        let usm = UsmSecurityParameters {
            msg_authoritative_engine_id,
            msg_authoritative_engine_boots,
            msg_authoritative_engine_time,
            msg_user_name: msg_user_name.to_string(),
            msg_authentication_parameters,
            msg_privacy_parameters,
        };
        Ok((i, usm))
    })(i)
}
