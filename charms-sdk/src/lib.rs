pub use charms_data as data;

#[macro_export]
macro_rules! main {
    ($path:path) => {
        fn main() {
            use charms_sdk::data::{App, Data, Transaction};

            let (app, tx, x, w): (App, Transaction, Data, Data) =
                charms_sdk::data::util::read(std::io::stdin())
                    .expect("should deserialize (app, tx, x, w): (App, Transaction, Data, Data)");
            assert!($path(&app, &tx, &x, &w));
        }
    };
}

/// Declare the version of a versioned Charms app module.
///
/// Expands to:
/// - `pub const VERSION: u32 = $version;` for use in the app's Rust code, and
/// - a `#[no_mangle] extern "C" fn __app_version() -> u32` export so the version is readable from
///   the compiled Wasm binary.
///
/// Use exactly once at the top of an app's `lib.rs`/`main.rs`. Spell prove and check will
/// verify that this value matches the `version` declared in [`NormalizedSpell::versioned_apps`].
///
/// ```ignore
/// charms_sdk::app_version!(1);
/// ```
#[macro_export]
macro_rules! app_version {
    ($version:expr) => {
        pub const VERSION: u32 = $version;
        #[unsafe(no_mangle)]
        pub extern "C" fn __app_version() -> u32 {
            VERSION
        }
    };
}
