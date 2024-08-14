use blockifier::execution::syscalls::hint_processor::SyscallExecutionError;
use cairo_vm::Felt252;
use starknet_crypto::{poseidon_hash_many, FieldElement};

use crate::starkware_utils::commitment_tree::base_types::Length;

/// Represents the structure of the bytecode to allow loading it partially into the OS memory.
/// See the documentation of the OS function `bytecode_hash_node` in `compiled_class.cairo`
/// for more details.
pub trait BytecodeSegmentStructure {}

/// All types implementing BytecodeSegmentStructure.
///
/// We use an enum to avoid Box<dyn BytecodeSegmentStructure>. We need structs in this module
/// to implement Clone and `BytecodeSegment.inner_structure` can refer to any struct implementing
/// `BytecodeSegmentStructure`.
#[derive(Clone, Debug)]
pub enum BytecodeSegmentStructureImpl {
    SegmentedNode(BytecodeSegmentedNode),
    Leaf(BytecodeLeaf),
}

impl BytecodeSegmentStructureImpl {
    pub fn hash(&self) -> Result<FieldElement, SyscallExecutionError> {
        let ret = match self {
            BytecodeSegmentStructureImpl::SegmentedNode(node) => node.hash()?,
            BytecodeSegmentStructureImpl::Leaf(data) => {
                let vec_field_elements: Result<Vec<_>, _> =
                    data.data.iter().map(|value| FieldElement::from_bytes_be(&value.to_bytes_be())).collect();

                match vec_field_elements {
                    Ok(elements) => poseidon_hash_many(&elements),
                    Err(_) => {
                        return Err(SyscallExecutionError::InternalError("Invalid bytecode segment leaf".into()).into());
                    }
                }
            }
        };

        Ok(ret)
    }
}

/// Represents a child of BytecodeSegmentedNode.
#[derive(Clone, Debug)]
pub struct BytecodeSegment {
    /// The length of the segment.
    pub segment_length: Length,
    /// Should the segment (or part of it) be loaded to memory.
    /// In other words, is the segment used during the execution.
    /// Note that if is_used is False, the entire segment is not loaded to memory.
    /// If is_used is True, it is possible that part of the segment will be skipped (according
    /// to the "is_used" field of the child segments).
    pub is_used: bool,
    /// The inner structure of the segment.
    pub inner_structure: BytecodeSegmentStructureImpl,
}

#[derive(Clone, Debug)]
pub struct BytecodeSegmentedNode {
    pub segments: Vec<BytecodeSegment>,
}

impl BytecodeSegmentedNode {
    pub fn hash(&self) -> Result<FieldElement, SyscallExecutionError> {
        let felts: Vec<_> = self
            .segments
            .iter()
            .flat_map(|segment| vec![FieldElement::from(segment.segment_length.0), segment.inner_structure.hash()?])
            .collect()?;

        Ok(poseidon_hash_many(&felts))
    }
}

/// Represents a leaf in the bytecode segment tree.
#[derive(Clone, Debug)]
pub struct BytecodeLeaf {
    pub data: Vec<Felt252>,
}
