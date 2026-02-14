mod script_asm;

use script_asm::{parse_script, ParseScriptError};

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[test]
fn parse_script_core_parity_vectors() {
    let in_out = [
        ("", ""),
        ("0", "00"),
        ("1", "51"),
        ("2", "52"),
        ("3", "53"),
        ("4", "54"),
        ("5", "55"),
        ("6", "56"),
        ("7", "57"),
        ("8", "58"),
        ("9", "59"),
        ("10", "5a"),
        ("11", "5b"),
        ("12", "5c"),
        ("13", "5d"),
        ("14", "5e"),
        ("15", "5f"),
        ("16", "60"),
        ("17", "0111"),
        ("-9", "0189"),
        ("0x17", "17"),
        ("'17'", "023137"),
        ("ELSE", "67"),
        ("NOP10", "b9"),
    ];

    let mut all_in = String::new();
    let mut all_out = String::new();
    for (input, expected_hex) in in_out {
        let parsed = parse_script(input).expect("parse");
        assert_eq!(to_hex(parsed.as_bytes()), expected_hex);
        all_in.push(' ');
        all_in.push_str(input);
        all_in.push(' ');
        all_out.push_str(expected_hex);
    }

    let parsed_all = parse_script(&all_in).expect("parse concatenated tokens");
    assert_eq!(to_hex(parsed_all.as_bytes()), all_out);
}

#[test]
fn parse_script_core_parity_errors() {
    assert!(matches!(
        parse_script("11111111111111111111"),
        Err(ParseScriptError::DecimalOutOfRange(_))
    ));
    assert!(matches!(
        parse_script("11111111111"),
        Err(ParseScriptError::DecimalOutOfRange(_))
    ));
    assert!(matches!(
        parse_script("OP_CHECKSIGADD"),
        Err(ParseScriptError::BadOpcode(_))
    ));
}
