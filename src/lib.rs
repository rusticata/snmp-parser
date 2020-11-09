//! [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
//! [![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
//! [![Build Status](https://travis-ci.org/rusticata/snmp-parser.svg?branch=master)](https://travis-ci.org/rusticata/snmp-parser)
//! [![Crates.io Version](https://img.shields.io/crates/v/snmp-parser.svg)](https://crates.io/crates/snmp-parser)
//!
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
        unused_import_braces, unused_qualifications)]
#![warn(
    missing_debug_implementations,
    /* missing_docs,
    rust_2018_idioms,*/
    unreachable_pub
)]
#![forbid(unsafe_code)]
#![deny(broken_intra_doc_links)]
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
