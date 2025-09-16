//! # SNMP Parser
//!
//! An SNMP parser, implemented with the [nom](https://github.com/Geal/nom)
//! parser combinator framework.
//!
//! It is written in pure Rust, fast, and makes extensive use of zero-copy.
//! It also aims to be panic-free.
//!
//! The goal of this parser is to implement SNMP messages analysis, for example
//! to use rules from a network IDS.
//!
//! To read a message, different functions must be used depending on the expected message
//! version.
//! This crate implements the [`asn1_rs::FromBer`] trait, so to parse a message, use the
//! expected object and call function `from_ber`.
//!
//! For example, to parse a SNMP v1 or v2c message (message structure is the same), use
//! [`SnmpMessage`]`::from_ber(input)`.
//! To parse a SNMP v3 message, use [`SnmpV3Message`]`::from_ber(input)`.
//! If you don't know the version of the message and want to parse a generic SNMP message,
//! use [`SnmpGenericMessage`]`::from_ber(input)`.
//!
//! Other methods of parsing (functions) are provided for compatibility:
//! these functions are [`parse_snmp_v1`](snmp/fn.parse_snmp_v1.html),
//! [`parse_snmp_v2c`](snmp/fn.parse_snmp_v2c.html) and
//! [`parse_snmp_v3`](snmpv3/fn.parse_snmp_v3.html).
//! If you don't know the version of the message and want to parse a generic SNMP message,
//! use the [`parse_snmp_generic_message`](fn.parse_snmp_generic_message.html) function.
//!
//! The code is available on [Github](https://github.com/rusticata/snmp-parser)
//! and is part of the [Rusticata](https://github.com/rusticata) project.

#![deny(/*missing_docs,*/unsafe_code,
        unstable_features,
        unused_import_braces, unused_qualifications)]
#![warn(
    missing_debug_implementations,
    /* missing_docs,
    rust_2018_idioms,*/
    unreachable_pub
)]
#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod generic;
mod usm;

pub mod error;
pub mod snmp;
pub mod snmpv3;

pub use generic::*;
pub use snmp::*;
pub use snmpv3::*;

// re-exports to prevent public dependency on asn1_rs
pub use asn1_rs;
pub use asn1_rs::{Oid, OidParseError};

#[cfg(test)]
mod tests {
    use asn1_rs::FromBer;

    use super::{SnmpGenericMessage, SnmpMessage, SnmpV3Message, SnmpVariable};

    #[allow(dead_code)]
    fn assert_is_fromber<'a, E, T: FromBer<'a, E>>() {}

    #[test]
    fn check_traits() {
        assert_is_fromber::<_, SnmpVariable>();
        assert_is_fromber::<_, SnmpMessage>();
        assert_is_fromber::<_, SnmpV3Message>();
        assert_is_fromber::<_, SnmpGenericMessage>();
    }
}
