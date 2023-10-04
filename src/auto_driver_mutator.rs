#![cfg(unix)]

use std::collections::HashMap;
use std::env;
use std::fmt::Debug;
use std::fs::File;
use std::io::{BufReader, Write};

use custom_mutator::{export_mutator, CustomMutator};
use env_logger::Env;
use log::{debug, info, log_enabled, trace, Level};
use serde_json::{Map, Value};

use crate::c_types::*;

pub struct AutoDriverMutator {
    pub(crate) decision_bits_per_iteration: usize,
    pub(crate) types: HashMap<String, Type>,
    pub(crate) functions: Vec<Function>,
    pub(crate) chaining_variables_size: usize,
    fuzz_vector: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct FunctionCall<'a> {
    pub(crate) function: &'a Function,
    pub(crate) chain_return_type: Option<bool>,
    pub(crate) arguments: Vec<FunctionArgument>,
}

#[derive(Debug)]
pub(crate) enum FunctionArgument {
    Basic(BasicType),
    FuzzInput(Type),
    Chained,
    PermanentlyChained,
}

impl CustomMutator for AutoDriverMutator {
    type Error = ();

    fn init(_seed: u32) -> Result<Self, Self::Error> {
        let _ = env_logger::Builder::from_env(Env::default().default_filter_or("debug")).try_init();
        info!("Initializing AutoDriver mutator!");

        // Open file
        let function_api_location = env::var("AUTO_DRIVER_FUNCTION_API_PATH").expect("Missing AUTO_DRIVER_FUNCTION_API_PATH environmental variable that specifies the location of the fuzz-driver-function-api-layout-json");
        info!("Reading API from: {}", function_api_location);
        let file = File::open(&function_api_location)
            .unwrap_or_else(|_| panic!("Could not open {}", function_api_location));
        let reader = BufReader::new(file);
        let json: Value = serde_json::from_reader(reader).unwrap();

        // Parse decision bits per iteration
        let decision_bits_per_iteration =
            json["decision_bits_per_iteration"].as_u64().unwrap() as usize;

        // Parse types
        info!("Parsing types:");
        let mut declarations = HashMap::<String, Option<Type>>::new();
        for declared_type in json["types"].as_array().unwrap() {
            info!("Declared type: {}", declared_type);
            let type_name = declared_type["name"].as_str().unwrap();
            assert_eq!(declarations.insert(String::from(type_name), None), None);
        }

        // Insert primitive types
        declarations.insert(
            String::from("void"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 0],
            })),
        );
        declarations.insert(
            String::from("char"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 1],
            })),
        );
        declarations.insert(
            String::from("signed char"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 1],
            })),
        );
        declarations.insert(
            String::from("unsigned char"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 1],
            })),
        );
        declarations.insert(
            String::from("short"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 2],
            })),
        );
        declarations.insert(
            String::from("signed short"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 2],
            })),
        );
        declarations.insert(
            String::from("unsigned short"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 2],
            })),
        );
        declarations.insert(
            String::from("int"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 4],
            })),
        );
        declarations.insert(
            String::from("signed int"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 4],
            })),
        );
        declarations.insert(
            String::from("unsigned int"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 4],
            })),
        );
        declarations.insert(
            String::from("long"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 8],
            })),
        );
        declarations.insert(
            String::from("signed long"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 8],
            })),
        );
        declarations.insert(
            String::from("unsigned long"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 8],
            })),
        );
        declarations.insert(
            String::from("signed long long"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 8],
            })),
        );
        declarations.insert(
            String::from("unsigned long long"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 8],
            })),
        );
        declarations.insert(
            String::from("float"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 4],
            })),
        );
        declarations.insert(
            String::from("double"),
            Some(Type::BasicType(BasicType {
                content: vec![0; 8],
            })),
        );
        // Insert function_prototype dummy
        declarations.insert(
            String::from("function_pointer"),
            Some(Type::FunctionPointer),
        );

        // Iterative type resolution
        info!("Resolving types:");
        while declarations.values().any(|v| v.is_none()) {
            let lookup_map = declarations.clone();
            for (type_name, type_option) in declarations.iter_mut() {
                if type_option.is_none() {
                    *type_option = resolve_type(type_name, &json, &lookup_map);
                }
            }
        }

        fn resolve_type(
            type_name: &str,
            json: &Value,
            declarations: &HashMap<String, Option<Type>>,
        ) -> Option<Type> {
            let datatype = json["types"]
                .as_array()
                .unwrap()
                .iter()
                .find(|current_type| current_type["name"].as_str().unwrap() == type_name)
                .unwrap();

            info!("Looking up: {}", datatype["name"]);
            match datatype["type"].as_str().unwrap() {
                "struct" => {
                    let mut elements = Vec::<Type>::new();
                    for t in datatype["fields"].as_array().unwrap().iter() {
                        info!("Looking up struct field: {}", t);
                        // Simple declaration
                        if let Some(type_name) = t.as_str() {
                            match declarations.get(type_name).unwrap() {
                                Some(t) => elements.push(t.clone()),
                                None => return None,
                            }
                        }
                        // Array declaration
                        else {
                            match resolve_array_or_pointer_type(
                                t.as_object().unwrap(),
                                declarations,
                            ) {
                                Some(t) => elements.push(t),
                                None => return None,
                            }
                        }
                    }
                    Some(Type::Struct(Struct { types: elements }))
                }
                "enum" => Some(Type::Enum(Enum { enum_variant: 0 })),
                "union" => {
                    let mut union_fields = Vec::<Type>::new();
                    for t in datatype["fields"].as_array().unwrap().iter() {
                        info!("Looking up union field: {}", t);
                        // Simple declaration
                        if let Some(type_name) = t.as_str() {
                            match declarations.get(type_name).expect("Undeclared type") {
                                Some(t) => union_fields.push(t.clone()),
                                None => {
                                    return None;
                                }
                            }
                        }
                        // Array declaration
                        else {
                            match resolve_array_or_pointer_type(
                                t.as_object().unwrap(),
                                declarations,
                            ) {
                                Some(t) => union_fields.push(t),
                                None => return None,
                            }
                        }
                    }
                    Some(Type::Union(Union {
                        union_variant: 0,
                        union_fields,
                    }))
                }
                "typedef" => {
                    if let Some(underlying) = datatype["underlying"].as_str() {
                        declarations
                            .get(underlying)
                            .expect("Undeclared type")
                            .as_ref()
                            .map(|t| {
                                Type::Typedef(TypeDef {
                                    internal_type: Box::new(t.clone()),
                                })
                            })
                    } else {
                        resolve_array_or_pointer_type(
                            datatype["underlying"].as_object().unwrap(),
                            declarations,
                        )
                    }
                }
                "function_pointer" => Some(Type::FunctionPointer),
                _ => {
                    panic!("Unknown type: {}", datatype)
                }
            }
        }
        fn resolve_array_or_pointer_type(
            t: &Map<String, Value>,
            declarations: &HashMap<String, Option<Type>>,
        ) -> Option<Type> {
            if let Some(array_element) = t.get("array_element") {
                let array_length = t["length"].as_u64().unwrap() as usize;
                return if let Some(t) = array_element.as_str() {
                    declarations.get(t).unwrap().as_ref().map(|t| {
                        Type::Array(Array {
                            elements: vec![t.clone(); array_length],
                        })
                    })
                } else {
                    resolve_array_or_pointer_type(array_element.as_object().unwrap(), declarations)
                        .map(|t| {
                            Type::Array(Array {
                                elements: vec![t; array_length],
                            })
                        })
                };
            } else if let Some(pointee) = t.get("pointee") {
                return if let Some(t) = pointee.as_str() {
                    Some(Type::Pointer(Pointer {
                        target_type_id: Some(t.to_string()),
                        elements: vec![],
                    }))
                } else {
                    resolve_array_or_pointer_type(pointee.as_object().unwrap(), declarations).map(
                        |t| {
                            Type::Pointer(Pointer {
                                target_type_id: None,
                                elements: vec![t],
                            })
                        },
                    )
                };
            } else {
                panic!("Unknown type: {:?}", t)
            }
        }
        let types: HashMap<String, Type> = declarations
            .clone()
            .into_iter()
            .map(|(k, v)| (k, v.expect("Could not resolve type")))
            .collect();

        fn lookup_type(
            t: &Value,
            types: &HashMap<String, Type>,
            declarations: &HashMap<String, Option<Type>>,
        ) -> Type {
            let mut t = if let Some(type_identifier) = t.as_str() {
                types[type_identifier].clone()
            } else {
                resolve_array_or_pointer_type(t.as_object().unwrap(), declarations)
                    .expect("All types must be declared and resolved at this stage")
            };
            while let Type::Typedef(underlying) = &t {
                t = *underlying.internal_type.clone();
            }
            t
        }

        // Parse functions
        info!("Parsing functions:");
        let mut functions: Vec<Function> = Vec::new();
        for declared_function in json["functions"].as_array().unwrap() {
            info!("Parsing function: {}", declared_function);
            let name = declared_function["name"].as_str().unwrap();

            let return_type = &declared_function["return_type"].as_object().unwrap()["type"];
            let return_type = lookup_type(return_type, &types, &declarations);
            info!("Return type: {:?}", return_type);

            let mut function = Function {
                name: name.to_string(),
                return_type,
                parameter_types: Vec::new(),
            };

            for function_parameter in declared_function["parameter_types"].as_array().unwrap() {
                info!("Looking up function parameter: {}", function_parameter);
                let opaque = function_parameter.as_object().unwrap()["opaque"]
                    .as_bool()
                    .unwrap();
                let parameter_type = &function_parameter.as_object().unwrap()["type"];
                let parameter_type = lookup_type(parameter_type, &types, &declarations);

                info!("{}: {:?}", name, parameter_type);
                info!("Opaque: {}", opaque);
                if !opaque {
                    function.parameter_types.push(parameter_type);
                } else {
                    function.parameter_types.push(Type::OpaquePointer);
                }
            }
            functions.push(function);
        }

        // Parse chaining variables
        info!("Parsing chaining variables:");
        let chaining_variables_size = json["minimal_init_chaining_variables_size"]
            .as_u64()
            .unwrap() as usize;
        info!(
            "Size of chaining variables section in bytes: {}",
            chaining_variables_size
        );

        info!("Function API parsed successfully!\n");
        Ok(Self {
            decision_bits_per_iteration,
            types,
            functions,
            chaining_variables_size,
            fuzz_vector: Vec::new(),
        })
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
        _add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Result<Option<&'b [u8]>, Self::Error> {
        debug!("New fuzz run!");
        debug!("Input:\n{:?}", buffer);
        debug!("Input length: {}", buffer.len());

        if cfg!(debug_assertions) {
            let mut file = File::create("/tmp/mutation_output").unwrap();
            file.write_all(buffer).unwrap();
        }

        // Initialize blank fuzz run
        if buffer.len() < self.chaining_variables_size + 2 {
            self.fuzz_vector = self.serialize_fuzz_run(&Vec::new());
            debug!("--Initialized fuzz vector--\n");
            debug!("Output:\n{:?}", self.fuzz_vector);
            debug!("Output length: {}", self.fuzz_vector.len());
            return Ok(Some(&self.fuzz_vector));
        }

        // Deserialize input fuzz run
        let mut called_functions = self.deserialize_fuzz_run(buffer);
        trace!("Functions before mutation:");
        if log_enabled!(Level::Trace) {
            for function in &called_functions {
                trace!("{:?}", function.function.name);
            }
        }

        // If we serialize and deserialize the fuzz run, it should not change
        if cfg!(debug_assertions) {
            debug_assert_eq!(
                self.serialize_fuzz_run(&called_functions),
                self.serialize_fuzz_run(
                    &self.deserialize_fuzz_run(&self.serialize_fuzz_run(&called_functions))
                )
            );
        }

        // Mutate the fuzz run
        self.mutate(&mut called_functions);
        debug!("Functions after mutation:");
        if log_enabled!(Level::Debug) {
            for function in &called_functions {
                debug!("{:?}", function.function.name);
            }
        }

        debug!("Iterations: {}", called_functions.len());

        // Serialize mutated fuzz run
        self.fuzz_vector = self.serialize_fuzz_run(&called_functions);

        debug!("Output:\n{:?}", self.fuzz_vector);
        debug!("Output length: {}", self.fuzz_vector.len());
        debug!("---Mutation complete---\n");

        if cfg!(debug_assertions) {
            let mut file = File::create("/tmp/mutation_output").unwrap();
            file.write_all(&self.fuzz_vector).unwrap();
        }

        if self.fuzz_vector.len() <= max_size {
            Ok(Some(&self.fuzz_vector))
        } else {
            debug!("Skipping mutation as it exceeds max_size!");
            Ok(None)
        }
    }
}

export_mutator!(AutoDriverMutator);
