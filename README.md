<!-- cargo-sync-readme start -->

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build Status](https://travis-ci.org/rusticata/snmp-parser.svg?branch=master)](https://travis-ci.org/rusticata/snmp-parser)
[![Crates.io Version](https://img.shields.io/crates/v/snmp-parser.svg)](https://crates.io/crates/snmp-parser)

# SNMP Parser

A SNMP parser, implemented with the [nom](https://github.com/Geal/nom)
parser combinator framework.

The goal of this parser is to implement SNMP messages analysis, for example
to use rules from a network IDS.

To read a message, different functions must be used depending on the expected message
version. The main functions for parsing are [`parse_snmp_v1`](https://docs.rs/snmp-parser/latest/snmp_parser/snmp/fn.parse_snmp_v1.html),
[`parse_snmp_v2c`](https://docs.rs/snmp-parser/latest/snmp_parser/snmp/fn.parse_snmp_v2c.html) and
[`parse_snmp_v3`](https://docs.rs/snmp-parser/latest/snmp_parser/snmpv3/fn.parse_snmp_v3.html).
If you don't know the version of the message and want to parse a generic SNMP message,
use the [`parse_snmp_generic_message`](https://docs.rs/snmp-parser/latest/snmp_parser/fn.parse_snmp_generic_message.html) function.

The code is available on [Github](https://github.com/rusticata/snmp-parser)
and is part of the [Rusticata](https://github.com/rusticata) project.
<!-- cargo-sync-readme end -->

## Changes

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
