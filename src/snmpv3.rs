//! SNMPv3 Parser
//!
//! SNMPv3 is defined in the following RFCs:
//!   - [RFC2570](https://tools.ietf.org/html/rfc2570): Introduction to SNMP v3
//!   - [RFC3412](https://tools.ietf.org/html/rfc3412): Message Processing and Dispatching for the
//!     Simple Network Management Protocol (SNMP)
//!
//! See also:
//!   - [RFC2578](https://tools.ietf.org/html/rfc2578): Structure of Management Information Version 2 (SMIv2)

use der_parser::*;
use nom::IResult;

use error::SnmpError;

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
    pub msg_security_model: u32,
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
    pub data: &'a[u8],
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
                msg_security_model: sm,
            }
        )
    ).map(|x| x.1)
}

fn parse_snmp_v3_plaintext_pdu<'a>(i:&'a[u8]) -> IResult<&'a[u8],ScopedPduData<'a>> {
    parse_der_struct!(
        i,
        ctx_eng_id: map_res!(parse_der_octetstring, |x: DerObject<'a>| x.as_slice()) >>
        ctx_name:   map_res!(parse_der_octetstring, |x: DerObject<'a>| x.as_slice()) >>
        data:       map_res!(parse_der, |x: DerObject<'a>| x.as_slice()) >>
        (
            ScopedPduData::Plaintext(ScopedPdu{
                ctx_engine_id: ctx_eng_id,
                ctx_engine_name: ctx_name,
                data: data
            })
        )
    ).map(|x| x.1)
}



#[cfg(test)]
mod tests {
    use snmpv3::*;
    use nom::IResult;

static SNMPV3_REQ: &'static [u8] = include_bytes!("../assets/snmpv3_req.bin");

#[test]
fn test_snmp_v3_req() {
    let empty = &b""[..];
    let bytes = SNMPV3_REQ;
    let sp = [48, 14, 4, 0, 2, 1, 0, 2, 1, 0, 4, 0, 4, 0, 4, 0];
    let cei = [0x80, 0x00, 0x1f, 0x88, 0x80, 0x59, 0xdc, 0x48, 0x61, 0x45, 0xa2, 0x63, 0x22];
    let data = [2, 4, 125, 14, 8, 46, 2, 1, 0, 2, 1, 0, 48, 0];
    let expected = IResult::Done(empty,SnmpV3Message{
        version: 3,
        header_data: HeaderData{
            msg_id: 821490644,
            msg_max_size: 65507,
            msg_flags: 4,
            msg_security_model: 3,
        },
        security_params: &sp,
        data: ScopedPduData::Plaintext(
            ScopedPdu{
                ctx_engine_id: &cei,
                ctx_engine_name: b"",
                data: &data,
            }
        ),
    });
    let res = parse_snmp_v3(&bytes);
    eprintln!("{:?}", res);
    assert_eq!(res, expected);
}


#[test]
fn test_snmp_v3_req_encrypted() {
    let bytes = include_bytes!("../assets/snmpv3_req_encrypted.bin");
    let res = parse_snmp_v3(bytes);
    eprintln!("{:?}", res);
}

}
