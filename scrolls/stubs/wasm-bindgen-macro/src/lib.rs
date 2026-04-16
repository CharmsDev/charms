use proc_macro::TokenStream;

/// No-op stub for wasm_bindgen attribute macro.
/// Passes through structs/enums/impls unchanged, but strips extern blocks
/// (which would declare JS FFI functions that don't exist on ICP).
#[proc_macro_attribute]
pub fn wasm_bindgen(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let input_str = input.to_string();
    // Strip extern "C" blocks — these declare JS FFI functions
    if input_str.trim_start().starts_with("extern") {
        return TokenStream::new();
    }
    input
}

/// No-op stub for __wasm_bindgen_class_marker attribute macro.
#[proc_macro_attribute]
pub fn __wasm_bindgen_class_marker(_attr: TokenStream, input: TokenStream) -> TokenStream {
    input
}

/// No-op stub for link_to attribute macro.
#[proc_macro_attribute]
pub fn link_to(_attr: TokenStream, input: TokenStream) -> TokenStream {
    input
}
