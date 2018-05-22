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
    NomError(u32)
}

impl From<u32> for SnmpError{
    fn from(e: u32) -> SnmpError {
        SnmpError::NomError(e)
    }
}
