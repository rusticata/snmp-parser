//! RFC2274 - User-based Security Model (USM) for version 3 of the Simple Network Management Protocol (SNMPv3)

use der_parser::{DerTag,parse_der_u32};
use snmp::parse_der_octetstring_as_slice;
use nom::IResult;
use std::str;

#[derive(Debug, PartialEq)]
pub struct UsmSecurityParameters<'a> {
    pub msg_authoritative_engine_id: &'a[u8],
    pub msg_authoritative_engine_boots: u32,
    pub msg_authoritative_engine_time: u32,
    pub msg_user_name: String,
    pub msg_authentication_parameters: &'a[u8],
    pub msg_privacy_parameters: &'a[u8],
}

pub fn parse_usm_security_parameters(i:&[u8]) -> IResult<&[u8],UsmSecurityParameters> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        eng_id: parse_der_octetstring_as_slice >>
        eng_b:  parse_der_u32 >>
        eng_t:  parse_der_u32 >>
        user:   map_res!(
                    parse_der_octetstring_as_slice,
                    str::from_utf8
                ) >>
        auth_p: parse_der_octetstring_as_slice >>
        priv_p: parse_der_octetstring_as_slice >>
        (
            UsmSecurityParameters{
                msg_authoritative_engine_id: eng_id,
                msg_authoritative_engine_boots: eng_b,
                msg_authoritative_engine_time: eng_t,
                msg_user_name: user.to_string(),
                msg_authentication_parameters: auth_p,
                msg_privacy_parameters: priv_p,
            }
        )
    ).map(|(rem,x)| (rem,x.1))
}
