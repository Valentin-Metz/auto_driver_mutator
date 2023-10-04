use log::debug;
use std::collections::HashMap;

use rand::prelude::SliceRandom;
use rand::rngs::ThreadRng;
use rand::Rng;

use crate::auto_driver_mutator::{AutoDriverMutator, FunctionArgument, FunctionCall};
use crate::c_types::Type;

#[macro_export]
macro_rules! call_random_function {
    ($arr:expr $(, $args:expr)*) => {
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..$arr.len());
        let method = $arr[index];
        method($($args),*);
    };
}
impl AutoDriverMutator {
    pub(crate) fn mutate<'b, 's: 'b>(&'s self, called_functions: &'b mut Vec<FunctionCall<'s>>) {
        let mut rng = rand::thread_rng();
        let fuzz_functions = [
            AutoDriverMutator::add_random_function_call,
            AutoDriverMutator::remove_random_function_call,
            AutoDriverMutator::mutate_random_function_call,
        ];
        call_random_function!(fuzz_functions, self, called_functions, &mut rng);
    }

    fn add_random_function_call<'b, 's: 'b>(
        &'s self,
        called_functions: &'b mut Vec<FunctionCall<'s>>,
        mut rng: &mut ThreadRng,
    ) {
        let function = self
            .functions
            .choose(&mut rng)
            .expect("No functions declared!");
        let mut arguments = Vec::new();
        for parameter_type in &function.parameter_types {
            match parameter_type {
                Type::BasicType(b) => {
                    arguments.push(FunctionArgument::Basic(b.clone()));
                }
                Type::OpaquePointer => {
                    arguments.push(FunctionArgument::PermanentlyChained);
                }
                _ => {
                    arguments.push(FunctionArgument::FuzzInput(parameter_type.clone()));
                }
            }
        }
        let chain_return_type = if function.return_type.has_chaining_bit() {
            Some(false)
        } else {
            None
        };
        debug!("Adding function call: {:?}", function);
        called_functions.push(FunctionCall {
            function,
            chain_return_type,
            arguments,
        });
    }

    fn remove_random_function_call<'b, 's: 'b>(
        &'s self,
        called_functions: &'b mut Vec<FunctionCall<'s>>,
        rng: &mut ThreadRng,
    ) {
        debug!("Removing random function call");
        if !called_functions.is_empty() {
            called_functions.remove(rng.gen_range(0..called_functions.len()));
        }
    }

    fn mutate_random_function_call<'b, 's: 'b>(
        &'s self,
        called_functions: &'b mut Vec<FunctionCall<'s>>,
        mut rng: &mut ThreadRng,
    ) {
        fn change_argument_type(
            argument: &mut FunctionArgument,
            _types: &HashMap<String, Type>,
            _rng: &mut ThreadRng,
        ) {
            match argument {
                FunctionArgument::Basic(_) => {}
                FunctionArgument::FuzzInput(t) => match t {
                    Type::Array(_) | Type::Pointer(_) | Type::FunctionPointer => {
                        debug!("Turning fuzz input argument {:?} into chained argument", t);
                        *argument = FunctionArgument::Chained;
                    }
                    _ => {
                        // Other types may be complex, but they are not chained, as they have no chaining variable
                    }
                },
                FunctionArgument::Chained => {} // Future option: enable revert to fuzz input
                FunctionArgument::PermanentlyChained => {}
            }
        }
        fn mutate_function_argument(
            argument: &mut FunctionArgument,
            types: &HashMap<String, Type>,
            rng: &mut ThreadRng,
        ) {
            match argument {
                FunctionArgument::Basic(b) => {
                    debug!("Mutating basic argument: {:?}", b);
                    b.mutate(types, rng);
                }
                FunctionArgument::FuzzInput(argument) => {
                    debug!("Mutating fuzz input argument: {:?}", argument);
                    argument.mutate(types, rng);
                }
                FunctionArgument::Chained => {
                    debug!("Skipping chained argument");
                }
                FunctionArgument::PermanentlyChained => {
                    debug!("Skipping permanently chained argument");
                }
            }
        }
        if let Some(selected_function_call) = called_functions.choose_mut(&mut rng) {
            debug!("Mutating function call: {:?}", selected_function_call);
            if let Some(chain_return_type) = selected_function_call.chain_return_type.as_mut() {
                *chain_return_type = rng.gen();
            }
            if let Some(selected_argument) = selected_function_call.arguments.choose_mut(&mut rng) {
                debug!("Mutating argument: {:?}", selected_argument);
                let function_argument_mutation_functions =
                    [change_argument_type, mutate_function_argument];
                call_random_function!(
                    function_argument_mutation_functions,
                    selected_argument,
                    &self.types,
                    &mut rng
                );
            }
        }
    }
}
