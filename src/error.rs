use asn1_rs::Error;
use nom::error::{ErrorKind, ParseError};
use std::convert::From;

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum SnmpError {
    #[error("Invalid message: not a DER sequence, or unexpected number of items, etc.")]
    InvalidMessage,
    #[error("Invalid version: not a number, or not in supported range (1, 2 or 3)")]
    InvalidVersion,
    #[error("Unknown or invalid PDU type")]
    InvalidPduType,
    #[error("Invalid PDU: content does not match type, or content cannot be decoded")]
    InvalidPdu,
    #[error("Invalid SNMPv3 header data")]
    InvalidHeaderData,
    #[error("Invalid SNMPv3 scoped PDU")]
    InvalidScopedPduData,
    #[error("Invalid SNMPv3 security model")]
    InvalidSecurityModel,
    #[error("Nom error")]
    NomError(ErrorKind),
    #[error("BER error")]
    BerError(Error),
}

impl<I> ParseError<I> for SnmpError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        SnmpError::NomError(kind)
    }
    fn append(_input: I, kind: ErrorKind, _other: Self) -> Self {
        SnmpError::NomError(kind)
    }
}

impl From<Error> for SnmpError {
    fn from(e: Error) -> SnmpError {
        SnmpError::BerError(e)
    }
}

impl From<SnmpError> for nom::Err<SnmpError> {
    fn from(e: SnmpError) -> nom::Err<SnmpError> {
        nom::Err::Error(e)
    }
}
