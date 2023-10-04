mod tests {
    use std::{env, fs};

    use custom_mutator::CustomMutator;

    use auto_driver_mutator::auto_driver_mutator::AutoDriverMutator;

    #[test]
    fn auto_driver_mutator_simple_arguments() {
        let function_api_location = env::var("CARGO_MANIFEST_DIR").unwrap()
            + "/tests/config_api/fuzzer_simpleArguments.json";
        env::set_var("AUTO_DRIVER_FUNCTION_API_PATH", function_api_location);
        let mut mutator = AutoDriverMutator::init(0).unwrap();
        let mut buffer = vec![0];
        for _ in 0..1024 {
            let mut buffer_clone = buffer.clone();
            buffer.clear();
            buffer.extend(
                mutator
                    .fuzz(&mut buffer_clone, None, usize::MAX)
                    .unwrap()
                    .unwrap(),
            );
        }
    }

    #[test]
    fn auto_driver_mutator_simple_pointer_arguments() {
        let function_api_location = env::var("CARGO_MANIFEST_DIR").unwrap()
            + "/tests/config_api/fuzzer_simplePointerArguments.json";
        env::set_var("AUTO_DRIVER_FUNCTION_API_PATH", function_api_location);
        let mut mutator = AutoDriverMutator::init(0).unwrap();
        let mut buffer = vec![0];
        for _ in 0..1024 {
            let mut buffer_clone = buffer.clone();
            buffer.clear();
            buffer.extend(
                mutator
                    .fuzz(&mut buffer_clone, None, usize::MAX)
                    .unwrap()
                    .unwrap(),
            );
        }
    }

    #[test]
    fn auto_driver_mutator_simple_pointer_inner_declaration() {
        let function_api_location = env::var("CARGO_MANIFEST_DIR").unwrap()
            + "/tests/config_api/fuzzer_simplePointerInnerDeclaration.json";
        env::set_var("AUTO_DRIVER_FUNCTION_API_PATH", function_api_location);
        let mut mutator = AutoDriverMutator::init(0).unwrap();
        let mut buffer = vec![0];
        for _ in 0..1024 {
            let mut buffer_clone = buffer.clone();
            buffer.clear();
            buffer.extend(
                mutator
                    .fuzz(&mut buffer_clone, None, usize::MAX)
                    .unwrap()
                    .unwrap(),
            );
        }
    }

    #[test]
    fn auto_driver_mutator_simple_pointer_typedef() {
        let function_api_location = env::var("CARGO_MANIFEST_DIR").unwrap()
            + "/tests/config_api/fuzzer_simplePointerTypedef.json";
        env::set_var("AUTO_DRIVER_FUNCTION_API_PATH", function_api_location);
        let mut mutator = AutoDriverMutator::init(0).unwrap();
        let mut buffer = vec![0];
        for _ in 0..1024 {
            let mut buffer_clone = buffer.clone();
            buffer.clear();
            buffer.extend(
                mutator
                    .fuzz(&mut buffer_clone, None, usize::MAX)
                    .unwrap()
                    .unwrap(),
            );
        }
    }

    #[test]
    fn auto_driver_mutator_simple_static_array_inner_declarations() {
        let function_api_location = env::var("CARGO_MANIFEST_DIR").unwrap()
            + "/tests/config_api/fuzzer_simpleStaticArrayInnerDeclarations.json";
        env::set_var("AUTO_DRIVER_FUNCTION_API_PATH", function_api_location);
        let mut mutator = AutoDriverMutator::init(0).unwrap();
        let mut buffer = vec![0];
        for _ in 0..1024 {
            let mut buffer_clone = buffer.clone();
            buffer.clear();
            buffer.extend(
                mutator
                    .fuzz(&mut buffer_clone, None, usize::MAX)
                    .unwrap()
                    .unwrap(),
            );
        }
    }

    #[test]
    fn auto_driver_mutator_simple_static_array_declaration() {
        let function_api_location = env::var("CARGO_MANIFEST_DIR").unwrap()
            + "/tests/config_api/fuzzer_simpleStaticArrayArguments.json";
        env::set_var("AUTO_DRIVER_FUNCTION_API_PATH", function_api_location);
        let mut mutator = AutoDriverMutator::init(0).unwrap();
        let mut buffer = vec![0];
        for _ in 0..1024 {
            let mut buffer_clone = buffer.clone();
            buffer.clear();
            buffer.extend(
                mutator
                    .fuzz(&mut buffer_clone, None, usize::MAX)
                    .unwrap()
                    .unwrap(),
            );
        }
    }

    #[test]
    fn auto_driver_mutator_complex_struct_fields() {
        let function_api_location = env::var("CARGO_MANIFEST_DIR").unwrap()
            + "/tests/config_api/fuzzer_complex_struct_fields.json";
        env::set_var("AUTO_DRIVER_FUNCTION_API_PATH", function_api_location);
        let mut mutator = AutoDriverMutator::init(0).unwrap();
        let mut buffer = vec![0];
        for _ in 0..1024 {
            let mut buffer_clone = buffer.clone();
            buffer.clear();
            buffer.extend(
                mutator
                    .fuzz(&mut buffer_clone, None, usize::MAX)
                    .unwrap()
                    .unwrap(),
            );
        }
    }

    #[test]
    fn auto_driver_mutator_function_pointer_directly_annotated() {
        let function_api_location = env::var("CARGO_MANIFEST_DIR").unwrap()
            + "/tests/config_api/fuzzer_functionPointerDirectlyAnnotated.json";
        env::set_var("AUTO_DRIVER_FUNCTION_API_PATH", function_api_location);
        let mut mutator = AutoDriverMutator::init(0).unwrap();
        let mut buffer = vec![0];
        for _ in 0..1024 {
            let mut buffer_clone = buffer.clone();
            buffer.clear();
            buffer.extend(
                mutator
                    .fuzz(&mut buffer_clone, None, usize::MAX)
                    .unwrap()
                    .unwrap(),
            );
        }
    }

    #[test]
    fn auto_driver_mutator_unrelated_combination_nonnull_opaque() {
        let function_api_location = env::var("CARGO_MANIFEST_DIR").unwrap()
            + "/tests/config_api/fuzzer_unrelated_combination_nonnull_opaque.json";
        env::set_var("AUTO_DRIVER_FUNCTION_API_PATH", function_api_location);
        let mut mutator = AutoDriverMutator::init(0).unwrap();
        let mut buffer = vec![0];
        for _ in 0..1024 {
            let mut buffer_clone = buffer.clone();
            buffer.clear();
            buffer.extend(
                mutator
                    .fuzz(&mut buffer_clone, None, usize::MAX)
                    .unwrap()
                    .unwrap(),
            );
        }
    }

    #[test]
    fn auto_driver_mutator_function_pointer() {
        let function_api_location = env::var("CARGO_MANIFEST_DIR").unwrap()
            + "/tests/config_api/fuzzer_functionPointer.json";
        env::set_var("AUTO_DRIVER_FUNCTION_API_PATH", function_api_location);
        let mut mutator = AutoDriverMutator::init(0).unwrap();
        let mut buffer = vec![0];
        for _ in 0..1024 {
            let mut buffer_clone = buffer.clone();
            buffer.clear();
            buffer.extend(
                mutator
                    .fuzz(&mut buffer_clone, None, usize::MAX)
                    .unwrap()
                    .unwrap(),
            );
        }
    }

    #[test]
    fn auto_driver_mutator_libpng_driver() {
        let function_api_location =
            env::var("CARGO_MANIFEST_DIR").unwrap() + "/tests/config_api/libpng_driver.json";
        env::set_var("AUTO_DRIVER_FUNCTION_API_PATH", function_api_location);
        let mut mutator = AutoDriverMutator::init(0).unwrap();
        let mut buffer = vec![0];
        for _ in 0..1024 {
            let mut buffer_clone = buffer.clone();
            buffer.clear();
            buffer.extend(
                mutator
                    .fuzz(&mut buffer_clone, None, usize::MAX)
                    .unwrap()
                    .unwrap(),
            );
        }
    }

    #[test]
    fn auto_driver_mutator_libsndfile_driver() {
        let function_api_location =
            env::var("CARGO_MANIFEST_DIR").unwrap() + "/tests/config_api/libsndfile_driver.json";
        env::set_var("AUTO_DRIVER_FUNCTION_API_PATH", function_api_location);
        let mut mutator = AutoDriverMutator::init(0).unwrap();
        let mut buffer = vec![0];
        for _ in 0..1024 {
            let mut buffer_clone = buffer.clone();
            buffer.clear();
            buffer.extend(
                mutator
                    .fuzz(&mut buffer_clone, None, usize::MAX)
                    .unwrap()
                    .unwrap(),
            );
        }
    }

    #[test]
    fn auto_driver_mutator_libtiff_driver() {
        let function_api_location =
            env::var("CARGO_MANIFEST_DIR").unwrap() + "/tests/config_api/libtiff_driver.json";
        env::set_var("AUTO_DRIVER_FUNCTION_API_PATH", function_api_location);
        let mut mutator = AutoDriverMutator::init(0).unwrap();
        let mut buffer = vec![0];
        for _ in 0..1024 {
            let mut buffer_clone = buffer.clone();
            buffer.clear();
            buffer.extend(
                mutator
                    .fuzz(&mut buffer_clone, None, usize::MAX)
                    .unwrap()
                    .unwrap(),
            );
        }
    }

    #[test]
    fn auto_driver_mutator_lz4_driver() {
        let function_api_location =
            env::var("CARGO_MANIFEST_DIR").unwrap() + "/tests/config_api/lz4_driver.json";
        env::set_var("AUTO_DRIVER_FUNCTION_API_PATH", function_api_location);
        let mut mutator = AutoDriverMutator::init(0).unwrap();
        let mut buffer = vec![0];
        for _ in 0..1024 {
            let mut buffer_clone = buffer.clone();
            buffer.clear();
            buffer.extend(
                mutator
                    .fuzz(&mut buffer_clone, None, usize::MAX)
                    .unwrap()
                    .unwrap(),
            );
        }
    }

    #[test]
    fn auto_driver_mutator_zlib_driver() {
        let function_api_location =
            env::var("CARGO_MANIFEST_DIR").unwrap() + "/tests/config_api/zlib_driver.json";
        env::set_var("AUTO_DRIVER_FUNCTION_API_PATH", function_api_location);
        let mut mutator = AutoDriverMutator::init(0).unwrap();
        let mut buffer = vec![0];
        for _ in 0..1024 {
            let mut buffer_clone = buffer.clone();
            buffer.clear();
            buffer.extend(
                mutator
                    .fuzz(&mut buffer_clone, None, usize::MAX)
                    .unwrap()
                    .unwrap(),
            );
        }
    }

    #[test]
    fn auto_driver_mutator_all_api_examples() {
        let function_api_folder = env::var("CARGO_MANIFEST_DIR").unwrap() + "/tests/config_api/";
        for api in fs::read_dir(function_api_folder).unwrap().flatten() {
            let function_api_location = api.path().to_str().unwrap().to_string();
            env::set_var("AUTO_DRIVER_FUNCTION_API_PATH", function_api_location);
            let mut mutator = AutoDriverMutator::init(0).unwrap();
            let mut buffer = vec![0];
            for _ in 0..1024 {
                let mut buffer_clone = buffer.clone();
                buffer.clear();
                buffer.extend(
                    mutator
                        .fuzz(&mut buffer_clone, None, usize::MAX)
                        .unwrap()
                        .unwrap(),
                );
            }
        }
    }
}
