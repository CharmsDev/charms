use charms_data::{App, Data};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::MapAccess, ser::SerializeMap};
use std::collections::BTreeMap;

/// Deserialize a map visiting entries in order, validating keys are sorted.
fn visit_sorted<'de, A: MapAccess<'de>>(mut map: A) -> Result<BTreeMap<App, Data>, A::Error> {
    let mut result = BTreeMap::new();
    let mut prev: Option<App> = None;
    while let Some((k_str, v)) = map.next_entry::<String, Data>()? {
        let k: App = k_str.parse().map_err(serde::de::Error::custom)?;
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

pub fn serialize<S>(map: &BTreeMap<App, Data>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        let mut ser = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            ser.serialize_entry(&k.to_string(), v)?;
        }
        ser.end()
    } else {
        map.serialize(serializer)
    }
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<App, Data>, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
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
    } else {
        BTreeMap::deserialize(deserializer)
    }
}
