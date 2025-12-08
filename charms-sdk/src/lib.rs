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
