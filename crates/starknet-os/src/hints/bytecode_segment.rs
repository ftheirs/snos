use std::collections::HashMap;

use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::insert_value_into_ap;
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use indoc::indoc;
use starknet_crypto::{poseidon_hash, poseidon_hash_many, FieldElement};
use starknet_os_types::hash::Hash;

use crate::hints::vars;
use crate::starknet::core::os::contract_class::compiled_class_hash_objects::BytecodeSegmentedNode;

pub const SET_AP_TO_SEGMENT_HASH: &str = indoc! {r#"
    memory[ap] = to_felt_or_relocatable(bytecode_segment_structure.hash())"#
};

pub fn set_ap_to_segment(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let bytecode_segment_structure: BytecodeSegmentedNode =
        exec_scopes.get(vars::scopes::BYTECODE_SEGMENT_STRUCTURE)?;

    // Calc hash
    let hash = bytecode_segment_structure.hash().map_err(|err| HintError::CustomHint((err.to_string())))?;

    // Insert to ap
    insert_value_into_ap(vm, Felt252::from(Hash::from_bytes_be(hash.to_bytes_be())));
    Ok(())
}
