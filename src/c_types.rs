use std::collections::HashMap;

use log::debug;
use rand::prelude::{SliceRandom, ThreadRng};
use rand::Rng;

use crate::{byte_vec_mutator, call_random_function};

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Type {
    Array(Array),
    Pointer(Pointer),
    OpaquePointer,
    Struct(Struct),
    Enum(Enum),
    Union(Union),
    Typedef(TypeDef),
    FunctionPointer,
    BasicType(BasicType),
}

impl Type {
    pub(crate) fn mutate(&mut self, types: &HashMap<String, Type>, rng: &mut ThreadRng) {
        debug!("Mutating type: {:?}", self);
        match self {
            Type::Array(a) => a.mutate(types, rng),
            Type::Pointer(p) => p.mutate(types, rng),
            Type::OpaquePointer => {}
            Type::Struct(s) => s.mutate(types, rng),
            Type::Enum(e) => e.mutate(types, rng),
            Type::Union(u) => u.mutate(types, rng),
            Type::Typedef(t) => t.mutate(types, rng),
            Type::FunctionPointer => {}
            Type::BasicType(b) => b.mutate(types, rng),
        }
    }
    pub(crate) fn has_chaining_bit(&self) -> bool {
        match self {
            Type::BasicType(_) => false,
            Type::Typedef(t) => t.internal_type.has_chaining_bit(),
            _ => true,
        }
    }
}

fn add_element(vec: &mut Vec<Type>, _: &HashMap<String, Type>, rng: &mut ThreadRng) {
    if let Some(random_element) = vec.choose(rng) {
        vec.push(random_element.clone());
    }
}
fn swap_elements(vec: &mut Vec<Type>, _: &HashMap<String, Type>, rng: &mut ThreadRng) {
    if !vec.is_empty() {
        let index_0 = rng.gen_range(0..vec.len());
        let index_1 = rng.gen_range(0..vec.len());
        vec.swap(index_0, index_1);
    }
}
fn mutate_element(vec: &mut Vec<Type>, types: &HashMap<String, Type>, rng: &mut ThreadRng) {
    if let Some(random_element) = vec.choose_mut(rng) {
        random_element.mutate(types, rng);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Array {
    pub elements: Vec<Type>,
}

impl Array {
    fn mutate(&mut self, types: &HashMap<String, Type>, rng: &mut ThreadRng) {
        let array_mutation_functions = [swap_elements, mutate_element];
        call_random_function!(array_mutation_functions, &mut self.elements, types, rng);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Pointer {
    pub target_type_id: Option<String>,
    pub elements: Vec<Type>,
}

impl Pointer {
    fn mutate(&mut self, types: &HashMap<String, Type>, rng: &mut ThreadRng) {
        if self.elements.is_empty() {
            self.elements
                .push(types[self.target_type_id.as_ref().unwrap()].clone());
        }
        let array_mutation_functions = [add_element, swap_elements, mutate_element];
        call_random_function!(array_mutation_functions, &mut self.elements, types, rng);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Struct {
    pub types: Vec<Type>,
}

impl Struct {
    fn mutate(&mut self, types: &HashMap<String, Type>, rng: &mut ThreadRng) {
        let array_mutation_functions = [mutate_element];
        call_random_function!(array_mutation_functions, &mut self.types, types, rng);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Enum {
    pub enum_variant: u32,
}

impl Enum {
    fn mutate(&mut self, _: &HashMap<String, Type>, rng: &mut ThreadRng) {
        self.enum_variant = rng.gen();
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Union {
    pub union_variant: usize,
    pub union_fields: Vec<Type>,
}

impl Union {
    fn change_variant(&mut self, _: &HashMap<String, Type>, rng: &mut ThreadRng) {
        self.union_variant = rng.gen_range(0..self.union_fields.len());
    }
    fn mutate_field(&mut self, types: &HashMap<String, Type>, rng: &mut ThreadRng) {
        self.union_fields[self.union_variant].mutate(types, rng);
    }
    fn mutate(&mut self, types: &HashMap<String, Type>, rng: &mut ThreadRng) {
        let union_mutation_functions = [Union::change_variant, Union::mutate_field];
        call_random_function!(union_mutation_functions, self, types, rng);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct TypeDef {
    pub internal_type: Box<Type>,
}

impl TypeDef {
    fn mutate(&mut self, types: &HashMap<String, Type>, rng: &mut ThreadRng) {
        self.internal_type.mutate(types, rng);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct BasicType {
    pub content: Vec<u8>,
}

impl BasicType {
    pub fn mutate(&mut self, _: &HashMap<String, Type>, rng: &mut ThreadRng) {
        let byte_vec_mutation_functions = [
            byte_vec_mutator::bit_flip_mutator,
            byte_vec_mutator::byte_flip_mutator,
            byte_vec_mutator::byte_inc_mutator,
            byte_vec_mutator::byte_dec_mutator,
            byte_vec_mutator::byte_neg_mutator,
            byte_vec_mutator::byte_rand_mutator,
            byte_vec_mutator::add_mutator_u8,
            byte_vec_mutator::add_mutator_u16,
            byte_vec_mutator::add_mutator_u32,
            byte_vec_mutator::add_mutator_u64,
            byte_vec_mutator::interesting_set_mutator_u8,
            byte_vec_mutator::interesting_set_mutator_u16,
            byte_vec_mutator::interesting_set_mutator_u32,
            byte_vec_mutator::bytes_set_mutator,
            byte_vec_mutator::bytes_random_set_mutator,
            byte_vec_mutator::bytes_copy_mutator,
            byte_vec_mutator::bytes_swap_mutator,
        ];
        if !self.content.is_empty() {
            call_random_function!(byte_vec_mutation_functions, &mut self.content, rng);
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Function {
    pub name: String,
    pub return_type: Type,
    pub parameter_types: Vec<Type>,
}
