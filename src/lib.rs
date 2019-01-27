//! # SNMP Parser
//!
//! A SNMP parser, implemented with the [nom](https://github.com/Geal/nom)
//! parser combinator framework.
//!
//! The goal of this parser is to implement SNMP messages analysis, for example
//! to use rules from a network IDS.
//!
//! To read a message, different functions must be used depending on the expected message
//! version. The main functions for parsing are [`parse_snmp_v1`](snmp/fn.parse_snmp_v1.html),
//! [`parse_snmp_v2c`](snmp/fn.parse_snmp_v2c.html) and
//! [`parse_snmp_v3`](snmpv3/fn.parse_snmp_v3.html).
//! If you don't know the version of the message and want to parse a generic SNMP message,
//! use the [`parse_snmp_generic_message`](fn.parse_snmp_generic_message.html) function.
//!
//! The code is available on [Github](https://github.com/rusticata/snmp-parser)
//! and is part of the [Rusticata](https://github.com/rusticata) project.

#![deny(/*missing_docs,*/unsafe_code,
        unstable_features,
        /*unused_import_braces,*/ unused_qualifications)]

#[macro_use]
extern crate nom;

#[macro_use]
extern crate rusticata_macros;

#[macro_use]
extern crate der_parser;

mod generic;
mod usm;

#[macro_use]
pub mod snmp;
pub mod snmpv3;
pub mod error;

pub use generic::*;
pub use snmp::*;
pub use snmpv3::*;
