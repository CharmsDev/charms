use charms_data::{App, Data};
use serde::{Deserializer, de::MapAccess};
use std::collections::BTreeMap;

/// Deserialize a map visiting entries in order, validating keys are sorted.
fn visit_sorted<'de, A: MapAccess<'de>>(mut map: A) -> Result<BTreeMap<App, Data>, A::Error> {
    let mut result = BTreeMap::new();
    let mut prev: Option<App> = None;
    while let Some((k, v)) = map.next_entry::<App, Data>()? {
        if let Some(ref p) = prev {
            if k <= *p {
                return Err(serde::de::Error::custom(format!(
                    "app keys must be in sorted order, but '{}' comes after '{}'",
                    k, p
                )));
            }
        }
        prev = Some(k.clone());
        result.insert(k, v);
    }
    Ok(result)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<App, Data>, D::Error>
where
    D: Deserializer<'de>,
{
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = BTreeMap<App, Data>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a map with App keys in sorted order")
        }
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            visit_sorted(map)
        }
    }
    deserializer.deserialize_map(V)
}
