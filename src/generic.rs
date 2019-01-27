use der_parser::*;
use nom::{Err,ErrorKind,IResult};
use snmp::*;
use snmpv3::*;
use std::str;

#[derive(Debug,PartialEq)]
pub enum SnmpGenericMessage<'a> {
    V1(SnmpMessage<'a>),
    V2(SnmpMessage<'a>),
    V3(SnmpV3Message<'a>),
}

pub fn parse_snmp_generic_message<'a>(i:&'a[u8]) -> IResult<&'a[u8],SnmpGenericMessage> {
    der_read_element_header(i).and_then(|(rem,hdr)| {
        if hdr.tag != DerTag::Sequence as u8 { return Err(Err::Error(error_position!(i, ErrorKind::Tag))); }
        take!(rem, hdr.len as usize)
    }).and_then(|(rem,data)| {
        parse_der_u32(data).and_then(|(r,version)| {
            match version {
                0 => {
                    do_parse!(
                        r,
                        community: map_res!(parse_der_octetstring_as_slice, str::from_utf8) >>
                        pdu:       parse_snmp_v1_pdu >>
                        (
                            SnmpGenericMessage::V1(SnmpMessage{
                                version,
                                community: community.to_string(),
                                pdu
                            })
                        )
                    )
                }
                1 => {
                    do_parse!(
                        r,
                        community: map_res!(parse_der_octetstring_as_slice, str::from_utf8) >>
                        pdu:       parse_snmp_v2c_pdu >>
                        (
                            SnmpGenericMessage::V2(SnmpMessage{
                                version,
                                community: community.to_string(),
                                pdu
                            })
                        )
                    )
                }
                3 => {
                    do_parse!(
                        r,
                        hdr:  parse_snmp_v3_headerdata >>
                        secp: map_res!(parse_der_octetstring, |x: DerObject<'a>| parse_secp(&x,&hdr)) >>
                        data: apply!(parse_snmp_v3_data,&hdr) >>
                        (
                            SnmpGenericMessage::V3(SnmpV3Message{
                                version,
                                header_data: hdr,
                                security_params: secp,
                                data
                            })
                        )
                    )
                },
                _ => { return Err(Err::Error(error_position!(i, ErrorKind::Tag))); }
            }
        }).map(|(_,res)| (rem,res)) // adjust remaining bytes
    })
}
