use bitcoin::{
    blockdata::script::{Builder, PushBytesBuf},
    opcodes::all,
    Script, ScriptBuf,
};

fn assert_expected_witness_program(script: &Script, expected_version: u8, expected_program: &[u8]) {
    assert!(script.is_witness_program(), "expected witness program");
    let actual_version = script.witness_version().expect("witness version");
    assert_eq!(actual_version.to_num(), expected_version);
    let bytes = script.as_bytes();
    assert_eq!(bytes.len(), expected_program.len() + 2);
    assert_eq!(&bytes[2..], expected_program);
}

fn assert_no_witness_program(script: &Script) {
    assert!(!script.is_witness_program(), "unexpected witness program");
    assert!(script.witness_version().is_none());
}

// Mirrors Bitcoin Core src/test/script_segwit_tests.cpp:IsPayToWitnessScriptHash_*.
#[test]
fn core_script_segwit_tests_is_p2wsh_detection_matrix() {
    let valid_program = vec![0u8; 32];
    let valid = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(PushBytesBuf::try_from(valid_program.clone()).expect("program bytes"))
        .into_script();
    assert!(valid.is_p2wsh());

    let mut direct = vec![all::OP_PUSHBYTES_0.to_u8(), 32];
    direct.extend([0u8; 32]);
    assert!(Script::from_bytes(&direct).is_p2wsh());

    let invalid_not_op0 = Builder::new()
        .push_opcode(all::OP_PUSHNUM_1)
        .push_slice(PushBytesBuf::try_from(vec![0u8; 32]).expect("program bytes"))
        .into_script();
    assert!(!invalid_not_op0.is_p2wsh());

    let invalid_size = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(PushBytesBuf::try_from(vec![0u8; 20]).expect("program bytes"))
        .into_script();
    assert!(!invalid_size.is_p2wsh());

    let invalid_nop = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_opcode(all::OP_NOP)
        .push_slice(PushBytesBuf::try_from(vec![0u8; 32]).expect("program bytes"))
        .into_script();
    assert!(!invalid_nop.is_p2wsh());

    assert!(!ScriptBuf::new().is_p2wsh());

    let mut pushdata1 = vec![all::OP_PUSHBYTES_0.to_u8(), all::OP_PUSHDATA1.to_u8(), 32];
    pushdata1.extend([0u8; 32]);
    assert!(!Script::from_bytes(&pushdata1).is_p2wsh());

    let mut pushdata2 = vec![
        all::OP_PUSHBYTES_0.to_u8(),
        all::OP_PUSHDATA2.to_u8(),
        32,
        0,
    ];
    pushdata2.extend([0u8; 32]);
    assert!(!Script::from_bytes(&pushdata2).is_p2wsh());

    let mut pushdata4 = vec![
        all::OP_PUSHBYTES_0.to_u8(),
        all::OP_PUSHDATA4.to_u8(),
        32,
        0,
        0,
        0,
    ];
    pushdata4.extend([0u8; 32]);
    assert!(!Script::from_bytes(&pushdata4).is_p2wsh());
}

// Mirrors Bitcoin Core src/test/script_segwit_tests.cpp:IsWitnessProgram_*.
#[test]
fn core_script_segwit_tests_is_witness_program_detection_matrix() {
    let min_program = vec![42u8, 18u8];
    let min_script = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(PushBytesBuf::try_from(min_program.clone()).expect("program bytes"))
        .into_script();
    assert_expected_witness_program(min_script.as_script(), 0, &min_program);

    let max_program = vec![7u8; 40];
    let max_script = Builder::new()
        .push_opcode(all::OP_PUSHNUM_16)
        .push_slice(PushBytesBuf::try_from(max_program.clone()).expect("program bytes"))
        .into_script();
    assert_expected_witness_program(max_script.as_script(), 16, &max_program);

    let v5_program = vec![3u8; 32];
    let mut direct = vec![all::OP_PUSHNUM_5.to_u8(), v5_program.len() as u8];
    direct.extend(v5_program.iter().copied());
    assert_expected_witness_program(Script::from_bytes(&direct), 5, &v5_program);

    let invalid_version = Builder::new()
        .push_opcode(all::OP_PUSHNUM_NEG1)
        .push_slice(PushBytesBuf::try_from(vec![0u8; 10]).expect("program bytes"))
        .into_script();
    assert_no_witness_program(invalid_version.as_script());

    let invalid_short = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(PushBytesBuf::try_from(vec![0u8; 1]).expect("program bytes"))
        .into_script();
    assert_no_witness_program(invalid_short.as_script());

    let invalid_long = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(PushBytesBuf::try_from(vec![0u8; 41]).expect("program bytes"))
        .into_script();
    assert_no_witness_program(invalid_long.as_script());

    let invalid_nop = Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_opcode(all::OP_NOP)
        .push_slice(PushBytesBuf::try_from(vec![0u8; 10]).expect("program bytes"))
        .into_script();
    assert_no_witness_program(invalid_nop.as_script());

    assert_no_witness_program(ScriptBuf::new().as_script());

    let mut pushdata1 = vec![all::OP_PUSHBYTES_0.to_u8(), all::OP_PUSHDATA1.to_u8(), 32];
    pushdata1.extend([0u8; 32]);
    assert_no_witness_program(Script::from_bytes(&pushdata1));

    let mut pushdata2 = vec![
        all::OP_PUSHBYTES_0.to_u8(),
        all::OP_PUSHDATA2.to_u8(),
        32,
        0,
    ];
    pushdata2.extend([0u8; 32]);
    assert_no_witness_program(Script::from_bytes(&pushdata2));

    let mut pushdata4 = vec![
        all::OP_PUSHBYTES_0.to_u8(),
        all::OP_PUSHDATA4.to_u8(),
        32,
        0,
        0,
        0,
    ];
    pushdata4.extend([0u8; 32]);
    assert_no_witness_program(Script::from_bytes(&pushdata4));
}
