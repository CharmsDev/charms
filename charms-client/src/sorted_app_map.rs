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

#[cfg(test)]
mod tests {
    use crate::NormalizedSpell;
    use charms_data::{App, Data};
    use serde_yaml::Mapping;
    use std::str::FromStr;
    use test_strategy::proptest;

    #[proptest]
    fn sorted_app_public_inputs_roundtrip(apps: Vec<App>) {
        let mut sorted_apps = apps.clone();
        sorted_apps.sort();

        let initially_sorted = apps == sorted_apps;

        // Create a spell with a single app (automatically sorted)
        let spell = NormalizedSpell::default();

        // Serialize to YAML
        let mut spell_value = serde_yaml::to_value(&spell).unwrap();

        let apps_data_mapping = apps.iter().map(|k| (k.clone(), Data::empty())).fold(
            Mapping::new(),
            |mut acc, (k, v)| {
                let k = serde_yaml::to_value(k).unwrap();
                let v = serde_yaml::to_value(v).unwrap();
                acc.insert(k, v);
                acc
            },
        );

        // let mut apps_data_value = serde_yaml::Value::Mapping(apps_data_mapping);

        let m = spell_value
            .get_mut("app_public_inputs")
            .unwrap()
            .as_mapping_mut()
            .unwrap();
        *m = apps_data_mapping;

        // Deserialize back
        let deserialized = serde_yaml::from_value::<NormalizedSpell>(spell_value);

        match initially_sorted {
            true => {
                assert!(deserialized.is_ok());
                let norm_spell = deserialized.unwrap();
                assert_eq!(
                    (norm_spell.app_public_inputs)
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>(),
                    apps
                );
            }
            false => {
                assert!(deserialized.is_err())
            }
        };
    }

    #[test]
    fn unsorted_app_public_inputs_rejected() {
        // Create two apps where the second is lexicographically smaller
        let app1 = App::from_str("t/0000000000000000000000000000000000000000000000000000000000000002/0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let app2 = App::from_str("t/0000000000000000000000000000000000000000000000000000000000000001/0000000000000000000000000000000000000000000000000000000000000001").unwrap();

        // Manually construct JSON with unsorted keys by ordering them in the JSON object
        // Note: serde_json maintains insertion order, so we need to construct manually
        let unsorted_json = format!(
            r#"{{"version":10,"tx":{{"ins":[],"outs":[]}},"app_public_inputs":{{"{}":null,"{}":null}}}}"#,
            app1, app2
        );

        // Attempt to deserialize should fail
        let result: Result<NormalizedSpell, _> = serde_json::from_str(&unsorted_json);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("app keys must be in sorted order"));
    }

    #[proptest]
    fn sorted_app_public_inputs_yaml_roundtrip(app: App) {
        let mut spell = NormalizedSpell::default();
        spell
            .app_public_inputs
            .insert(app.clone(), Default::default());

        // Serialize to YAML
        let yaml = serde_yaml::to_string(&spell).unwrap();

        // Deserialize back
        let deserialized: NormalizedSpell = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(deserialized.app_public_inputs, spell.app_public_inputs);
    }
}
