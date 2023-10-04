use std::collections::HashMap;

use log::trace;

use crate::auto_driver_mutator::{AutoDriverMutator, FunctionArgument, FunctionCall};
use crate::c_types::{Array, BasicType, Enum, Pointer, Struct, Type, TypeDef};

impl AutoDriverMutator {
    pub(crate) fn deserialize_fuzz_run(&self, buffer: &[u8]) -> Vec<FunctionCall> {
        trace!("Starting deserialization!");
        let mut buffer_iterator = buffer.iter();
        // Deserialize number of iterations
        let number_of_iterations = u16::from_le_bytes([
            *buffer_iterator.next().unwrap(),
            *buffer_iterator.next().unwrap(),
        ]);
        trace!(
            "Deserialized number of iterations: {:?}",
            number_of_iterations
        );
        // Deserialize decision bits
        trace!("Deserializing decision bits!");
        let decisions = match number_of_iterations {
            0 => Vec::new(),
            _ => bitfield_to_bool_vec(buffer_iterator.by_ref().take(
                ((self.decision_bits_per_iteration * number_of_iterations as usize) - 1) / 8 + 1,
            ))
            .chunks_exact(self.decision_bits_per_iteration)
            .take(number_of_iterations as usize)
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<Vec<bool>>>(),
        };
        trace!(
            "Expecting {} decision bits in {} bytes",
            self.decision_bits_per_iteration * number_of_iterations as usize,
            decisions.len(),
        );

        fn deserialize_type(
            t: &Type,
            types: &HashMap<String, Type>,
            buffer_iterator: &mut std::slice::Iter<u8>,
        ) -> Type {
            trace!("Deserializing type: {:?}", t);
            match t {
                Type::Array(a) => {
                    let mut elements = Vec::new();
                    for _ in &a.elements {
                        elements.push(deserialize_type(&a.elements[0], types, buffer_iterator));
                    }
                    Type::Array(Array { elements })
                }
                Type::Pointer(p) => {
                    let mut elements = Vec::new();
                    trace!("Consuming 2 bytes");
                    let length = u16::from_le_bytes([
                        *buffer_iterator.next().unwrap(),
                        *buffer_iterator.next().unwrap(),
                    ]);
                    for _ in 0..length {
                        elements.push(deserialize_type(
                            p.elements.first().unwrap_or_else(|| {
                                types.get(&p.target_type_id.clone().unwrap()).unwrap()
                            }),
                            types,
                            buffer_iterator,
                        ));
                    }
                    debug_assert!(p.target_type_id.is_some() || !elements.is_empty());
                    Type::Pointer(Pointer {
                        target_type_id: p.target_type_id.clone(),
                        elements,
                    })
                }
                Type::OpaquePointer => Type::OpaquePointer,
                Type::Struct(s) => {
                    let mut struct_types = Vec::new();
                    for t in &s.types {
                        struct_types.push(deserialize_type(t, types, buffer_iterator));
                    }
                    Type::Struct(Struct {
                        types: struct_types,
                    })
                }
                Type::Enum(_) => {
                    trace!("Consuming 4 bytes");
                    let enum_variant = u32::from_le_bytes([
                        *buffer_iterator.next().unwrap(),
                        *buffer_iterator.next().unwrap(),
                        *buffer_iterator.next().unwrap(),
                        *buffer_iterator.next().unwrap(),
                    ]);
                    Type::Enum(Enum { enum_variant })
                }
                Type::Union(u) => {
                    const U8_MAX: usize = u8::MAX as usize;
                    const U16_MAX: usize = u16::MAX as usize;
                    const U32_MAX: usize = u32::MAX as usize;
                    const U64_MAX: usize = u64::MAX as usize;
                    let mut union = u.clone();
                    match u.union_fields.len() {
                        0..=U8_MAX => {
                            trace!("Consuming 1 byte");
                            union.union_variant =
                                u8::from_le_bytes([*buffer_iterator.next().unwrap()]) as usize;
                        }
                        0..=U16_MAX => {
                            trace!("Consuming 2 bytes");
                            union.union_variant = u16::from_le_bytes([
                                *buffer_iterator.next().unwrap(),
                                *buffer_iterator.next().unwrap(),
                            ]) as usize;
                        }
                        0..=U32_MAX => {
                            trace!("Consuming 4 bytes");
                            union.union_variant = u32::from_le_bytes([
                                *buffer_iterator.next().unwrap(),
                                *buffer_iterator.next().unwrap(),
                                *buffer_iterator.next().unwrap(),
                                *buffer_iterator.next().unwrap(),
                            ]) as usize;
                        }
                        0..=U64_MAX => {
                            trace!("Consuming 8 bytes");
                            union.union_variant = u64::from_le_bytes([
                                *buffer_iterator.next().unwrap(),
                                *buffer_iterator.next().unwrap(),
                                *buffer_iterator.next().unwrap(),
                                *buffer_iterator.next().unwrap(),
                                *buffer_iterator.next().unwrap(),
                                *buffer_iterator.next().unwrap(),
                                *buffer_iterator.next().unwrap(),
                                *buffer_iterator.next().unwrap(),
                            ]) as usize;
                        }
                        _ => {
                            panic!("Union too large")
                        }
                    }
                    union.union_fields[union.union_variant] = deserialize_type(
                        &u.union_fields[union.union_variant],
                        types,
                        buffer_iterator,
                    );
                    Type::Union(union)
                }
                Type::Typedef(t) => Type::Typedef(TypeDef {
                    internal_type: Box::new(deserialize_type(
                        &t.internal_type,
                        types,
                        buffer_iterator,
                    )),
                }),
                Type::FunctionPointer => Type::FunctionPointer,
                Type::BasicType(b) => {
                    let mut content = Vec::new();
                    trace!("Consuming {} bytes", b.content.len());
                    for _ in 0..b.content.len() {
                        content.push(*buffer_iterator.next().unwrap());
                    }
                    Type::BasicType(BasicType { content })
                }
            }
        }

        trace!(
            "Chaining variable bytes & Fuzz input bytes: {:?}",
            buffer_iterator.clone()
        );
        trace!(
            "Chaining variable bytes & Fuzz input bytes length: {}",
            buffer_iterator.len()
        );

        // Deserialize chaining variables
        trace!("-----------------------------------");
        trace!("Deserializing chaining variables!");
        trace!(
            "Skipping {} chaining variable bytes",
            self.chaining_variables_size
        );
        for _ in 0..self.chaining_variables_size {
            buffer_iterator.next();
        }

        trace!("-----------------------------------");
        trace!("Deserializing fuzz input!");
        trace!("Fuzz input bytes: {:?}", buffer_iterator.clone());
        let called_functions = decisions
            .iter()
            .take(number_of_iterations as usize)
            .map(|run| run.iter())
            .fold(Vec::new(), |mut called_functions, mut run| {
                for function in self.functions.iter() {
                    trace!(
                        "Deserializing decision bits for function {:?}",
                        function.name
                    );
                    trace!("Getting 1 bit: Is function active?");
                    let active = *run.next().unwrap();
                    let mut function_call = FunctionCall {
                        function,
                        chain_return_type: if function.return_type.has_chaining_bit() {
                            if let Type::FunctionPointer = &function.return_type {
                                None
                            } else {
                                trace!(
                                    "Getting 1 bit: Store return type {:?} on chain?",
                                    function.return_type
                                );
                                Some(*run.next().unwrap())
                            }
                        } else {
                            None
                        },
                        arguments: Vec::new(),
                    };
                    for argument in function.parameter_types.iter() {
                        if let Type::OpaquePointer = argument {
                            function_call
                                .arguments
                                .push(FunctionArgument::PermanentlyChained);
                        } else if !argument.has_chaining_bit() {
                            if active {
                                if let Type::BasicType(b) =
                                    deserialize_type(argument, &self.types, &mut buffer_iterator)
                                {
                                    function_call.arguments.push(FunctionArgument::Basic(b));
                                } else {
                                    panic!("If it has no decision bit it must be a basic type!");
                                }
                            }
                        } else {
                            trace!("Getting 1 bit: Argument {:?} is read from chain?", argument);
                            let chaining_active = *run.next().unwrap(); // <- consumes bit
                            if active {
                                if chaining_active {
                                    match argument {
                                        Type::Array(_)
                                        | Type::Pointer(_)
                                        | Type::FunctionPointer => {
                                            function_call.arguments.push(FunctionArgument::Chained);
                                        }
                                        _ => {
                                            unreachable!("This type should not be chained")
                                        }
                                    }
                                } else {
                                    match argument {
                                        Type::BasicType(_) => {
                                            unreachable!("BasicTypes are handled above")
                                        }
                                        _ => {
                                            function_call.arguments.push(
                                                FunctionArgument::FuzzInput(deserialize_type(
                                                    argument,
                                                    &self.types,
                                                    &mut buffer_iterator,
                                                )),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if active {
                        called_functions.push(function_call);
                    }
                }
                called_functions
            });
        trace!("-----------------------------------");
        trace!("Deserialization complete!");
        trace!("-----------------------------------\n");
        called_functions
    }

    pub(crate) fn serialize_fuzz_run(&self, called_functions: &Vec<FunctionCall>) -> Vec<u8> {
        trace!("Starting serialization!");
        let mut buffer = Vec::new();
        // Serialize number of iterations
        let number_of_iterations = called_functions.len() as u16;
        buffer.extend_from_slice(&(number_of_iterations).to_le_bytes());
        trace!("Number of iterations:{:?}", number_of_iterations);
        trace!("Number of iterations bytes:{:?}", buffer);
        // Serialize decision bits
        let mut decisions = Vec::new();
        for function_call in called_functions.iter() {
            for function in self.functions.iter() {
                trace!(
                    "Deserializing decision bits for function {:?}",
                    function.name
                );
                trace!("Storing 1 bit: Is function active?");
                decisions.push(function_call.function.name == function.name);
                if function.return_type.has_chaining_bit() {
                    if let Type::FunctionPointer = &function.return_type {
                        // Do nothing
                    } else {
                        trace!(
                            "Storing 1 bit: Store return type {:?} on chain?",
                            function.return_type
                        );
                        decisions.push(
                            function_call.function.name == function.name
                                && function_call.chain_return_type.unwrap(),
                        );
                    }
                }
                for (i, argument) in function.parameter_types.iter().enumerate() {
                    if let Type::OpaquePointer = argument {
                        // Do nothing
                    } else if argument.has_chaining_bit() {
                        if function_call.function.name != function.name {
                            trace!("Storing 1 bit: Argument {:?} is read from chain?", argument);
                            decisions.push(false);
                        } else {
                            match function_call.arguments[i] {
                                FunctionArgument::FuzzInput(_) => {
                                    decisions.push(false);
                                }
                                FunctionArgument::Chained => {
                                    decisions.push(true);
                                }
                                _ => {
                                    unreachable!(
                                        "This FunctionArguments do not have decision bits"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        trace!(
            "Expecting {} decision bits",
            number_of_iterations as usize * self.decision_bits_per_iteration
        );
        trace!("Calculated that we have {} decision bits", decisions.len());
        debug_assert_eq!(
            decisions.len(),
            number_of_iterations as usize * self.decision_bits_per_iteration
        );
        trace!(
            "Decision bits bytes:\n{:?}",
            &bool_slice_to_bitfield(&mut decisions)
        );
        trace!(
            "Decision bits bytes length: {}",
            &bool_slice_to_bitfield(&mut decisions).len()
        );
        buffer.extend_from_slice(&bool_slice_to_bitfield(&mut decisions));

        fn serialize_type(t: &Type, buffer: &mut Vec<u8>) {
            match t {
                Type::Array(a) => {
                    for t in a.elements.iter() {
                        serialize_type(t, buffer);
                    }
                }
                Type::Pointer(p) => {
                    buffer.extend_from_slice(&(p.elements.len() as u16).to_le_bytes());
                    for t in p.elements.iter() {
                        serialize_type(t, buffer);
                    }
                }
                Type::OpaquePointer => {}
                Type::Struct(s) => {
                    for t in s.types.iter() {
                        serialize_type(t, buffer);
                    }
                }
                Type::Enum(e) => {
                    buffer.extend_from_slice(&(e.enum_variant).to_le_bytes());
                }
                Type::Union(u) => {
                    const U8_MAX: usize = u8::MAX as usize;
                    const U16_MAX: usize = u16::MAX as usize;
                    const U32_MAX: usize = u32::MAX as usize;
                    const U64_MAX: usize = u64::MAX as usize;
                    match u.union_fields.len() {
                        0..=U8_MAX => {
                            buffer.extend_from_slice(&(u.union_variant as u8).to_le_bytes());
                        }
                        0..=U16_MAX => {
                            buffer.extend_from_slice(&(u.union_variant as u16).to_le_bytes());
                        }
                        0..=U32_MAX => {
                            buffer.extend_from_slice(&(u.union_variant as u32).to_le_bytes());
                        }
                        0..=U64_MAX => {
                            buffer.extend_from_slice(&(u.union_variant as u64).to_le_bytes());
                        }
                        _ => {
                            panic!("Union too large")
                        }
                    }
                    serialize_type(&u.union_fields[u.union_variant], buffer);
                }
                Type::Typedef(t) => {
                    serialize_type(&t.internal_type, buffer);
                }
                Type::FunctionPointer => {} // only decision bits
                Type::BasicType(b) => {
                    buffer.extend_from_slice(&b.content);
                }
            }
        }

        // Serialize chaining variables
        trace!(
            "Serializing {} chaining variable bytes",
            self.chaining_variables_size
        );
        buffer.extend((0..self.chaining_variables_size).map(|_| 0));

        // Serialize fuzz input
        let mut fuzz_input_bytes = Vec::new();
        for function_call in called_functions.iter() {
            for argument in function_call.arguments.iter() {
                match argument {
                    FunctionArgument::Basic(b) => {
                        serialize_type(&Type::BasicType(b.clone()), &mut fuzz_input_bytes);
                    }
                    FunctionArgument::FuzzInput(t) => {
                        serialize_type(t, &mut fuzz_input_bytes);
                    }
                    FunctionArgument::Chained => {}
                    FunctionArgument::PermanentlyChained => {}
                }
            }
        }
        trace!("Serialized fuzz input bytes:\n{:?}", fuzz_input_bytes);
        trace!("Fuzz input bytes length: {}", fuzz_input_bytes.len());
        buffer.extend(fuzz_input_bytes);
        buffer
    }
}
fn bitfield_to_bool_vec<'a>(bytes: impl Iterator<Item = &'a u8>) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.size_hint().0 * 8);
    for byte in bytes {
        for i in (0..8).rev() {
            bits.push(byte & (1 << i) != 0);
        }
    }
    bits
}

fn bool_slice_to_bitfield(bool_vec: &mut Vec<bool>) -> Vec<u8> {
    while bool_vec.len() % 8 != 0 {
        bool_vec.push(false);
    }
    bool_vec
        .chunks_exact(8)
        .map(|chunk| {
            chunk
                .iter()
                .rev()
                .enumerate()
                .fold(0u8, |acc, (index, &value)| acc | ((value as u8) << index))
        })
        .collect()
}
