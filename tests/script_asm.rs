use bitcoin::{
    blockdata::script::{Builder, PushBytesBuf, ScriptBuf},
    hex::FromHex,
    opcodes::{all, Opcode},
};
use core::fmt;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug)]
pub enum ParseScriptError {
    BadDecimal(String),
    DecimalOutOfRange(i64),
    BadOpcode(String),
}

impl fmt::Display for ParseScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseScriptError::BadDecimal(tok) => write!(f, "bad decimal literal `{tok}`"),
            ParseScriptError::DecimalOutOfRange(n) => write!(
                f,
                "decimal out of range: {n} (allowed: -0xffffffff..=0xffffffff)"
            ),
            ParseScriptError::BadOpcode(tok) => write!(f, "unknown opcode `{tok}`"),
        }
    }
}

type OpcodeMap = HashMap<String, Opcode>;
static CORE_OPCODE_MAP: OnceLock<OpcodeMap> = OnceLock::new();

fn core_opcode_map() -> &'static OpcodeMap {
    CORE_OPCODE_MAP.get_or_init(build_core_opcode_map)
}

fn build_core_opcode_map() -> OpcodeMap {
    let mut map = HashMap::new();
    for byte in 0u8..=255 {
        let opcode = Opcode::from(byte);
        let name = match byte {
            0xb1 => "OP_CHECKLOCKTIMEVERIFY".into(),
            0xb2 => "OP_CHECKSEQUENCEVERIFY".into(),
            _ => opcode.to_string(),
        };

        if name == "OP_UNKNOWN" {
            continue;
        }
        let is_reserved = name == "OP_RESERVED";
        if byte < all::OP_NOP.to_u8() && !is_reserved {
            continue;
        }

        map.insert(name.clone(), opcode);
        if let Some(bare) = name.strip_prefix("OP_") {
            map.insert(bare.to_string(), opcode);
        }
    }
    map
}

pub fn parse_opcode(token: &str) -> Result<Opcode, ParseScriptError> {
    core_opcode_map()
        .get(token)
        .copied()
        .ok_or_else(|| ParseScriptError::BadOpcode(token.to_string()))
}

fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn parse_decimal_i64(s: &str) -> Result<i64, ParseScriptError> {
    let num_i64 = s
        .parse()
        .map_err(|_| ParseScriptError::BadDecimal(s.to_string()))?;
    const LIM: i64 = 0xffff_ffff;
    if !(-LIM..=LIM).contains(&num_i64) {
        return Err(ParseScriptError::DecimalOutOfRange(num_i64));
    }
    Ok(num_i64)
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

enum Token<'a> {
    Decimal(i64),
    Hex(Vec<u8>),
    Quoted(&'a str),
    Opcode(Opcode),
}

fn classify(token: &str) -> Result<Token<'_>, ParseScriptError> {
    if is_all_digits(token)
        || (token.starts_with('-') && token.len() > 1 && is_all_digits(&token[1..]))
    {
        Ok(Token::Decimal(parse_decimal_i64(token)?))
    } else if token.starts_with("0x") && token.len() > 2 && is_hex(&token[2..]) {
        let hex = Vec::from_hex(&token[2..]).expect("valid hex literal");
        Ok(Token::Hex(hex))
    } else if token.len() >= 2 && token.starts_with('\'') && token.ends_with('\'') {
        Ok(Token::Quoted(&token[1..token.len() - 1]))
    } else {
        Ok(Token::Opcode(parse_opcode(token)?))
    }
}

pub fn parse_script(s: &str) -> Result<ScriptBuf, ParseScriptError> {
    if s.trim().is_empty() {
        return Ok(ScriptBuf::new());
    }
    let mut out = Vec::new();
    for part in s.split([' ', '\t', '\n']).filter(|w| !w.is_empty()) {
        match classify(part)? {
            Token::Decimal(value) => {
                out.extend_from_slice(Builder::new().push_int(value).into_script().as_bytes());
            }
            Token::Hex(bytes) => out.extend_from_slice(&bytes),
            Token::Quoted(body) => {
                let push = PushBytesBuf::try_from(body.as_bytes().to_vec())
                    .map_err(|_| ParseScriptError::BadOpcode(part.to_string()))?;
                out.extend_from_slice(Builder::new().push_slice(push).into_script().as_bytes());
            }
            Token::Opcode(op) => {
                out.extend_from_slice(Builder::new().push_opcode(op).into_script().as_bytes())
            }
        }
    }
    Ok(ScriptBuf::from_bytes(out))
}
