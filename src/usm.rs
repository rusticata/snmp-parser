//! RFC2274 - User-based Security Model (USM) for version 3 of the Simple Network Management Protocol (SNMPv3)

use der_parser::{DerObject,DerTag,parse_der_integer,parse_der_octetstring};
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

pub fn parse_usm_security_parameters<'a>(i:&'a[u8]) -> IResult<&'a[u8],UsmSecurityParameters<'a>> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        eng_id: map_res!(parse_der_octetstring, |x:DerObject<'a>| x.as_slice()) >>
        eng_b:  map_res!(parse_der_integer, |x:DerObject| x.as_u32()) >>
        eng_t:  map_res!(parse_der_integer, |x:DerObject| x.as_u32()) >>
        user:   map_res!(
                    map_res!(parse_der_octetstring, |x:DerObject<'a>| x.as_slice()),
                    str::from_utf8
                ) >>
        auth_p: map_res!(parse_der_octetstring, |x:DerObject<'a>| x.as_slice()) >>
        priv_p: map_res!(parse_der_octetstring, |x:DerObject<'a>| x.as_slice()) >>
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
    ).map(|x| x.1)
}
