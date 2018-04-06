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
use nom::{IResult,ErrorKind};

use error::SnmpError;

#[derive(Debug,PartialEq)]
pub struct SnmpV3Message<'a> {
    pub version: u32,
    pub header_data: HeaderData,
    pub security_params: &'a[u8],
    pub data: ScopedPduData<'a>,
    // pub data: DerObject<'a>,
}

impl<'a> SnmpV3Message<'a> {
    pub fn from_der(obj: DerObject<'a>) -> Result<(&[u8],SnmpV3Message),SnmpError> {
    if let DerObjectContent::Sequence(ref v) = obj.content {
        if v.len() != 4 { return Err(SnmpError::InvalidMessage); };
        let vers = match v[0].content.as_u32() {
            Ok (u) => u,
            _      => return Err(SnmpError::InvalidMessage),
        };
        let header_data = HeaderData::from_der(&v[1])?;
        let security_params = match v[2].content.as_slice() {
            Ok(p) => p,
            _     => return Err(SnmpError::InvalidMessage),
        };
        let pdu = if header_data.is_encrypted()
        {
            let data = v[3].as_slice().or(Err(SnmpError::InvalidMessage))?;
            ScopedPduData::Encrypted(data)
        } else {
            ScopedPduData::from_der(v[3].clone())? // XXX useless clone to avoid moving data ?
        };
        Ok((&b""[..],
           SnmpV3Message{
               version: vers,
               header_data: header_data,
               security_params: security_params,
               data: pdu,
           }
          ))
    } else {
        Err(SnmpError::InvalidMessage)
    }
    }
}

#[derive(Debug,PartialEq)]
pub struct HeaderData {
    pub msg_id: u32,
    pub msg_max_size: u32,
    pub msg_flags: u8,
    pub msg_security_model: u32,
}

impl HeaderData {
    pub fn from_der(obj: &DerObject) -> Result<HeaderData,SnmpError> {
        if let DerObjectContent::Sequence(ref v) = obj.content {
            if v.len() != 4 { return Err(SnmpError::InvalidHeaderData); }
            let msg_id = v[0].as_u32().or(Err(SnmpError::InvalidHeaderData))?;
            let msg_max_size = v[1].as_u32().or(Err(SnmpError::InvalidHeaderData))?;
            let msg_flags = v[2].as_slice().or(Err(SnmpError::InvalidHeaderData))?;
            let msg_security_model = v[3].as_u32().or(Err(SnmpError::InvalidHeaderData))?;
            Ok(HeaderData{
                msg_id: msg_id,
                msg_max_size: msg_max_size,
                msg_flags: msg_flags[0] as u8,
                msg_security_model: msg_security_model,
            })
        } else {
            Err(SnmpError::InvalidMessage)
        }
    }

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

impl<'a> ScopedPduData<'a> {
    pub fn from_der(obj: DerObject) -> Result<ScopedPduData,SnmpError> {
        if let DerObjectContent::Sequence(ref v) = obj.content {
            if v.len() != 3 { return Err(SnmpError::InvalidScopedPduData); }
            let ctx_engine_id = v[0].as_slice().or(Err(SnmpError::InvalidScopedPduData))?;
            let ctx_engine_name = v[1].as_slice().or(Err(SnmpError::InvalidScopedPduData))?;
            let data = v[2].as_slice().or(Err(SnmpError::InvalidScopedPduData))?;
            Ok(ScopedPduData::Plaintext(ScopedPdu{
                ctx_engine_id: ctx_engine_id,
                ctx_engine_name: ctx_engine_name,
                data: data,
            }))
        } else {
            Err(SnmpError::InvalidMessage)
        }
    }
}




pub fn parse_snmp_v3_content<'a>(obj: DerObject<'a>) -> IResult<&'a[u8],SnmpV3Message<'a>,SnmpError> {
    match SnmpV3Message::from_der(obj) {
        Ok((rem,m))  => IResult::Done(rem,m),
        Err(e)       => IResult::Error(error_code!(ErrorKind::Custom(e))),
    }
}

pub fn parse_snmp_v3<'a>(i:&'a[u8]) -> IResult<&'a[u8],SnmpV3Message<'a>,SnmpError> {
    flat_map!(
        i,
        fix_error!(SnmpError,
                   parse_der_sequence_defined!(
                       parse_der_integer,
                       parse_snmp_v3_headerdata,
                       parse_der_octetstring,
                       parse_der // type is ANY
                       )
                   ),
        parse_snmp_v3_content
    )
}

fn parse_snmp_v3_headerdata<'a>(i:&'a[u8]) -> IResult<&'a[u8],DerObject<'a>> {
    parse_der_sequence_defined!(
        i,
        parse_der_integer,
        parse_der_integer,
        parse_der_octetstring,
        parse_der_integer
    )
}

fn parse_snmp_v3_plaintext_pdu<'a>(i:&'a[u8]) -> IResult<&'a[u8],ScopedPduData<'a>> {
    map_res!(i,parse_snmp_v3_scoped_pdu,ScopedPduData::from_der)
}

fn parse_snmp_v3_scoped_pdu<'a>(i:&'a[u8]) -> IResult<&'a[u8],DerObject<'a>> {
    parse_der_sequence_defined!(
        i,
        parse_der_octetstring,
        parse_der_octetstring,
        parse_der
    )
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
