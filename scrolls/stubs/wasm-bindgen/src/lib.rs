/// Stub prelude module for ICP canister compatibility.
pub mod prelude {
    pub use super::JsValue;
    pub use super::UnwrapThrowExt;
    pub use wasm_bindgen_macro::__wasm_bindgen_class_marker;
    pub use wasm_bindgen_macro::wasm_bindgen;
}

/// Stub trait that maps to regular unwrap on non-JS targets.
pub trait UnwrapThrowExt<T> {
    fn unwrap_throw(self) -> T;
    fn expect_throw(self, message: &str) -> T;
}

impl<T, E: core::fmt::Debug> UnwrapThrowExt<T> for Result<T, E> {
    fn unwrap_throw(self) -> T {
        self.unwrap()
    }
    fn expect_throw(self, message: &str) -> T {
        self.expect(message)
    }
}

impl<T> UnwrapThrowExt<T> for Option<T> {
    fn unwrap_throw(self) -> T {
        self.unwrap()
    }
    fn expect_throw(self, message: &str) -> T {
        self.expect(message)
    }
}

pub use wasm_bindgen_macro::__wasm_bindgen_class_marker;
pub use wasm_bindgen_macro::link_to;
pub use wasm_bindgen_macro::wasm_bindgen;

/// Implementation detail referenced by the `wasm_bindgen` proc-macro
/// expansion. Re-exports the helper-attribute-declaring derive so field-level
/// `#[wasm_bindgen(skip)]` etc. type-check.
#[doc(hidden)]
pub mod __rt {
    pub use wasm_bindgen_macro::BindgenedStruct;
}

/// Stub JsValue type for ICP canister compatibility.
pub struct JsValue {
    _private: (),
}

impl JsValue {
    pub const NULL: JsValue = JsValue { _private: () };
    pub const UNDEFINED: JsValue = JsValue { _private: () };
}

impl core::fmt::Debug for JsValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "JsValue(stub)")
    }
}

impl core::fmt::Display for JsValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "JsValue(stub)")
    }
}
