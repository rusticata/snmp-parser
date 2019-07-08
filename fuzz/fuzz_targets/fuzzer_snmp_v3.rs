#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate snmp_parser;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let _ = snmp_parser::parse_snmp_v3(data);
});
