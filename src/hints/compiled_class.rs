use std::collections::HashMap;

use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;

use crate::hints::vars;
use crate::starknet::core::os::contract_class::compiled_class_hash_objects::{BytecodeSegment, BytecodeSegmentedNode};

pub const ASSIGN_BYTECODE_SEGMENTS: &str = indoc! {r#"
    bytecode_segments = iter(bytecode_segment_structure.segments)"#
};

pub fn assign_bytecode_segments(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let bytecode_segment_structure: BytecodeSegmentedNode =
        exec_scopes.get(vars::scopes::BYTECODE_SEGMENT_STRUCTURE)?;

    let bytecode_segments = bytecode_segment_structure.segments.into_iter();
    exec_scopes.insert_value(vars::scopes::BYTECODE_SEGMENTS, bytecode_segments);

    Ok(())
}

pub const ASSERT_END_OF_BYTECODE_SEGMENTS: &str = indoc! {r#"
    assert next(bytecode_segments, None) is None"#
};
pub fn assert_end_of_bytecode_segments(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let mut bytecode_segments: <Vec<BytecodeSegment> as IntoIterator>::IntoIter = exec_scopes.get(vars::scopes::BYTECODE_SEGMENTS)?;
    if let Some(_) = bytecode_segments.next() {
        return Err(HintError::AssertionFailed("bytecode_segments is not exhausted".to_string().into_boxed_str()));
    }

    Ok(())
}

