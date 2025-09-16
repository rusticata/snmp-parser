![Maintenance](https://img.shields.io/badge/maintenance-activly--developed-brightgreen.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build Status](https://travis-ci.org/rusticata/snmp-parser.svg?branch=master)](https://travis-ci.org/rusticata/snmp-parser)
[![Crates.io Version](https://img.shields.io/crates/v/snmp-parser.svg)](https://crates.io/crates/snmp-parser)

<!-- cargo-rdme start -->

# SNMP Parser

An SNMP parser, implemented with the [nom](https://github.com/Geal/nom)
parser combinator framework.

It is written in pure Rust, fast, and makes extensive use of zero-copy.
It also aims to be panic-free.

The goal of this parser is to implement SNMP messages analysis, for example
to use rules from a network IDS.

To read a message, different functions must be used depending on the expected message
version.
This crate implements the [`asn1_rs::FromBer`] trait, so to parse a message, use the
expected object and call function `from_ber`.

For example, to parse a SNMP v1 or v2c message (message structure is the same), use
[`SnmpMessage`]`::from_ber(input)`.
To parse a SNMP v3 message, use [`SnmpV3Message`]`::from_ber(input)`.
If you don't know the version of the message and want to parse a generic SNMP message,
use [`SnmpGenericMessage`]`::from_ber(input)`.

Other methods of parsing (functions) are provided for compatibility:
these functions are [`parse_snmp_v1`](snmp/fn.parse_snmp_v1.html),
[`parse_snmp_v2c`](snmp/fn.parse_snmp_v2c.html) and
[`parse_snmp_v3`](snmpv3/fn.parse_snmp_v3.html).
If you don't know the version of the message and want to parse a generic SNMP message,
use the [`parse_snmp_generic_message`](fn.parse_snmp_generic_message.html) function.

The code is available on [Github](https://github.com/rusticata/snmp-parser)
and is part of the [Rusticata](https://github.com/rusticata) project.

<!-- cargo-rdme end -->

## Changes

### 0.11.0

- Update asn1-rs to 0.7
- Update thiserror to 2.0
- Fix clippy warnings: elided lifetime has a name
- Use `#[from]` instead of From impl for asn1 error
- Re-export `Oid` and `OidParseError`
- Fix renamed lint
- Implement `FromBer` for all top-level messages

Thanks: @MattesWhite

### 0.10.0

- Update asn1-rs to 0.6

### 0.9.0

- Convert to asn1-rs
- Set MSRV to 1.57

### 0.8.0

- Upgrade to nom 7 / der-parser 6

### 0.7.0

- Upgrade to nom 6 / der-parser 5

### 0.6.0

- Upgrade to der-parser 4

### 0.5.2

- Use `parse_ber_u32` from der-parser crate

### 0.5.1

- Fix parsing: use BER parsing so DER constraints are not applied

### 0.5.0

- Upgrade to nom 5 and der-parser 3

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
