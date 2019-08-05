use der_parser::error::BerError;
use nom::error::{ErrorKind, ParseError};
use std::convert::From;

#[derive(Debug,PartialEq)]
pub enum SnmpError {
    /// Invalid message: not a DER sequence, or unexpected number of items, etc.
    InvalidMessage,
    /// Invalid version: not a number, or not in supported range (1, 2 or 3)
    InvalidVersion,
    /// Unknown or invalid PDU type
    InvalidPduType,
    /// Invalid PDU: content does not match type, or content cannot be decoded
    InvalidPdu,
    /// Invalid SNMPv3 header data
    InvalidHeaderData,
    /// Invalid SNMPv3 scoped PDU
    InvalidScopedPduData,
    /// Nom error
    NomError(ErrorKind),
    BerError(BerError),
}

impl<I> ParseError<I> for SnmpError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        SnmpError::NomError(kind)
    }
    fn append(_input: I, kind: ErrorKind, _other: Self) -> Self {
        SnmpError::NomError(kind)
    }
}

impl From<BerError> for SnmpError{
    fn from(e: BerError) -> SnmpError {
        SnmpError::BerError(e)
    }
}
