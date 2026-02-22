use anyhow::{Result, anyhow, ensure};
use ark_std::{
    cmp::Ordering,
    collections::BTreeMap,
    format,
    str::FromStr,
    string::{String, ToString},
    vec::Vec,
};
use ciborium::Value;
use core::{convert::TryInto, fmt};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer, de,
    de::{DeserializeOwned, SeqAccess, Visitor},
    ser::SerializeTuple,
};
use serde_with::{IfIsHumanReadable, hex::Hex, serde_as};
pub mod util;

/// Macro to check a condition and return false (early) if it does not hold.
/// This is useful for checking pre-requisite conditions in predicate-type functions.
/// Inspired by the `ensure!` macro from the `anyhow` crate.
/// The function must return a boolean.
/// Example:
/// ```rust
/// use charms_data::check;
///
/// fn b_is_multiple_of_a(a: u32, b: u32) -> bool {
///     check!(a <= b && a != 0);    // returns false early if `a` is greater than `b` or `a` is zero
///     match b % a {
///         0 => true,
///         _ => false,
///     }
/// }
#[macro_export]
macro_rules! check {
    ($condition:expr) => {
        if !$condition {
            eprintln!("condition does not hold: {}", stringify!($condition));
            return false;
        }
    };
}

/// Represents a transaction involving Charms.
/// A Charms transaction sits on top of a Bitcoin transaction. Therefore, it transforms a set of
/// input UTXOs into a set of output UTXOs.
/// A Charms transaction may also reference other valid UTXOs that are not being spent or created.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    /// Input UTXOs.
    pub ins: Vec<(UtxoId, Charms)>,
    /// Reference UTXOs.
    pub refs: Vec<(UtxoId, Charms)>,
    /// Output charms.
    pub outs: Vec<Charms>,
    /// Amounts of native coin in inputs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coin_ins: Option<Vec<NativeOutput>>,
    /// Amounts of native coin in outputs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coin_outs: Option<Vec<NativeOutput>>,
    /// Previous transactions (creating outputs spent by this transaction) by transaction ID.
    pub prev_txs: BTreeMap<TxId, Data>,
    /// All apps used in this transaction with their public inputs.
    pub app_public_inputs: BTreeMap<App, Data>,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NativeOutput {
    pub amount: u64,
    #[serde_as(as = "IfIsHumanReadable<Hex>")]
    pub dest: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub content: Option<Data>,
}

/// Charms are tokens, NFTs or instances of arbitrary app state.
/// This type alias represents a collection of charms.
/// Structurally it is a map of `app -> data`.
pub type Charms = BTreeMap<App, Data>;

/// ID of a UTXO (Unspent Transaction Output) in the underlying ledger system (e.g. Bitcoin).
/// A UTXO ID is a pair of `(transaction ID, index of the output)`.
#[cfg_attr(any(test, feature = "test"), derive(test_strategy::Arbitrary))]
#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct UtxoId(pub TxId, pub u32);

impl UtxoId {
    /// Convert to a byte array (of 36 bytes).
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut bytes = [0u8; 36];
        bytes[..32].copy_from_slice(&self.0.0); // Copy TxId
        bytes[32..].copy_from_slice(&self.1.to_le_bytes()); // Copy index as little-endian
        bytes
    }

    /// Create `UtxoId` from a byte array (of 36 bytes).
    pub fn from_bytes(bytes: [u8; 36]) -> Self {
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(&bytes[..32]);
        let index = u32::from_le_bytes(bytes[32..].try_into().expect("exactly 4 bytes expected"));
        UtxoId(TxId(txid_bytes), index)
    }

    fn to_string_internal(&self) -> String {
        format!("{}:{}", self.0.to_string(), self.1)
    }
}

impl FromStr for UtxoId {
    type Err = anyhow::Error;

    /// Try to create `UtxoId` from a string in the format `txid_hex:index`.
    /// Example:
    /// ```
    /// use std::str::FromStr;
    /// use charms_data::UtxoId;
    /// let utxo_id = UtxoId::from_str("92077a14998b31367efeec5203a00f1080facdb270cbf055f09b66ae0a273c7d:3").unwrap();
    /// ```
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow!("expected format: txid_hex:index"));
        }

        let txid = TxId::from_str(parts[0])?;

        let index = parts[1]
            .parse::<u32>()
            .map_err(|e| anyhow!("invalid index: {}", e))?;

        Ok(UtxoId(txid, index))
    }
}

impl fmt::Display for UtxoId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string_internal().fmt(f)
    }
}

impl fmt::Debug for UtxoId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UtxoId({})", self.to_string_internal())
    }
}

impl Serialize for UtxoId {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(self.to_bytes().as_ref())
        }
    }
}

impl<'de> Deserialize<'de> for UtxoId {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UtxoIdVisitor;

        impl<'de> Visitor<'de> for UtxoIdVisitor {
            type Value = UtxoId;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string in format 'txid_hex:index' or a tuple (TxId, u32)")
            }

            // Handle human-readable format ("txid_hex:index")
            fn visit_str<E>(self, value: &str) -> Result<UtxoId, E>
            where
                E: de::Error,
            {
                UtxoId::from_str(value).map_err(E::custom)
            }

            // Handle non-human-readable byte format [u8; 36]
            fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(UtxoId::from_bytes(v.try_into().map_err(|e| {
                    E::custom(format!("invalid utxo_id bytes: {}", e))
                })?))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(UtxoIdVisitor)
        } else {
            deserializer.deserialize_bytes(UtxoIdVisitor)
        }
    }
}

/// App represents an application that can be used to create, transform or destroy charms (tokens,
/// NFTs and other instances of app data).
///
/// An app is identified by a single character `tag`, a 32-byte `identity` and a 32-byte `vk`
/// (verification key).
/// The `tag` is a single character that represents the type of the app, with two special values:
/// - `TOKEN` (tag `t`) for tokens,
/// - `NFT` (tag `n`) for NFTs.
///
/// Other values of `tag` are perfectly legal. The above ones are special: tokens and NFTs can be
/// transferred without providing the app's implementation (RISC-V binary).
///
/// The `vk` is a 32-byte byte string (hash) that is used to verify proofs that the app's contract
/// is satisfied (against the certain transaction, additional public input and private input).
///
/// The `identity` is a 32-byte byte string (hash) that uniquely identifies the app among other apps
/// implemented using the same code.
#[cfg_attr(any(test, feature = "test"), derive(proptest_derive::Arbitrary))]
#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct App {
    pub tag: char,
    pub identity: B32,
    pub vk: B32,
}

impl FromStr for App {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        // Split the string at '/'
        let mut parts = value.split('/').collect::<Vec<&str>>();
        let mut parts = parts.as_mut_slice();
        ensure!(parts.len() >= 3);
        if parts[0].is_empty() && parts[1].is_empty() {
            parts = &mut parts[1..];
            parts[0] = "/";
        }
        ensure!(
            parts.len() == 3,
            "expected format: tag_char/identity_hex/vk_hex"
        );

        let tag = char::from_str(parts[0]).map_err(|e| anyhow!(e))?;

        let identity = B32::from_str(parts[1]).map_err(|e| anyhow!(e))?;

        let vk = B32::from_str(parts[2]).map_err(|e| anyhow!(e))?;

        Ok(App { tag, identity, vk })
    }
}

impl fmt::Display for App {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}/{}", self.tag, self.identity, self.vk)
    }
}

impl fmt::Debug for App {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "App({}/{}/{})", self.tag, self.identity, self.vk)
    }
}

impl Serialize for App {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            let mut s = serializer.serialize_tuple(3)?;
            s.serialize_element(&self.tag)?;
            s.serialize_element(&self.identity)?;
            s.serialize_element(&self.vk)?;
            s.end()
        }
    }
}

impl<'de> Deserialize<'de> for App {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AppVisitor;

        impl<'de> Visitor<'de> for AppVisitor {
            type Value = App;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string in format 'tag_char/identity_hex/vk_hex' or a struct with tag, identity and vk fields")
            }

            // Handle human-readable format ("tag_char/identity_hex/vk_hex")
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                App::from_str(value).map_err(E::custom)
            }

            fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let tag = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::missing_field("tag"))?;
                let identity = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::missing_field("identity"))?;
                let vk = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::missing_field("vk"))?;

                Ok(App { tag, identity, vk })
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(AppVisitor)
        } else {
            deserializer.deserialize_tuple(3, AppVisitor)
        }
    }
}

/// ID (hash) of a transaction in the underlying ledger (Bitcoin).
#[cfg_attr(any(test, feature = "test"), derive(proptest_derive::Arbitrary))]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct TxId(pub [u8; 32]);

impl TxId {
    fn to_string_internal(&self) -> String {
        let mut txid = self.0;
        txid.reverse();
        hex::encode(&txid)
    }
}

impl FromStr for TxId {
    type Err = anyhow::Error;

    /// Try to create `TxId` from a string of 64 hex characters.
    /// Note that string representation of transaction IDs in Bitcoin is reversed, and so is ours
    /// (for compatibility).
    ///
    /// Example:
    /// ```
    /// use std::str::FromStr;
    /// use charms_data::TxId;
    /// let tx_id = TxId::from_str("92077a14998b31367efeec5203a00f1080facdb270cbf055f09b66ae0a273c7d").unwrap();
    /// ```
    fn from_str(s: &str) -> Result<Self> {
        ensure!(s.len() == 64, "expected 64 hex characters");
        let bytes = hex::decode(s).map_err(|e| anyhow!("invalid txid hex: {}", e))?;
        let mut txid: [u8; 32] = bytes.try_into().expect("exactly 32 bytes expected");
        txid.reverse();
        Ok(TxId(txid))
    }
}

impl fmt::Display for TxId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string_internal().fmt(f)
    }
}

impl fmt::Debug for TxId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TxId({})", self.to_string_internal())
    }
}

impl Serialize for TxId {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for TxId {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TxIdVisitor;

        impl<'de> Visitor<'de> for TxIdVisitor {
            type Value = TxId;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string of 64 hex characters or a byte array of 32 bytes")
            }

            // Handle human-readable format ("txid_hex")
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                TxId::from_str(value).map_err(E::custom)
            }

            // Handle non-human-readable byte format [u8; 32]
            fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(TxId(v.try_into().map_err(|e| {
                    E::custom(format!("invalid txid bytes: {}", e))
                })?))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(TxIdVisitor)
        } else {
            deserializer.deserialize_bytes(TxIdVisitor)
        }
    }
}

/// 32-byte byte string (e.g. a hash, like SHA256).
#[cfg_attr(any(test, feature = "test"), derive(proptest_derive::Arbitrary))]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct B32(pub [u8; 32]);

impl FromStr for B32 {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ensure!(s.len() == 64, "expected 64 hex characters");
        let bytes = hex::decode(s).map_err(|e| anyhow!("invalid hex: {}", e))?;
        let hash: [u8; 32] = bytes.try_into().expect("exactly 32 bytes expected");
        Ok(B32(hash))
    }
}

impl AsRef<[u8]> for B32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for B32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex::encode(&self.0).fmt(f)
    }
}

impl fmt::Debug for B32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Bytes32({})", hex::encode(&self.0))
    }
}

impl Serialize for B32 {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            let mut seq = serializer.serialize_tuple(32)?;
            for &byte in &self.0 {
                seq.serialize_element(&byte)?;
            }
            seq.end()
        }
    }
}

impl<'de> Deserialize<'de> for B32 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct B32Visitor;

        impl<'de> Visitor<'de> for B32Visitor {
            type Value = B32;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string of 64 hex characters or a sequence of 32 bytes")
            }

            // Handle human-readable format ("hex")
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                B32::from_str(value).map_err(E::custom)
            }

            // Handle non-human-readable byte format [u8; 32]
            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = [0u8; 32];
                for i in 0..32 {
                    bytes[i] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &"32 elements"))?;
                }

                // Check if there are extra elements
                if seq.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(33, &"exactly 32 elements"));
                }

                Ok(B32(bytes))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(B32Visitor)
        } else {
            deserializer.deserialize_tuple(32, B32Visitor)
        }
    }
}

/// Represents a data value that is guaranteed to be serialized/deserialized to/from CBOR.
#[derive(Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Data(Value);

impl Eq for Data {}

impl Ord for Data {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .partial_cmp(&other.0)
            .expect("Value comparison should have succeeded") // PANIC: will panic if CBOR Value comparison returns None (NaN or incomparable). We expect this to never happen (famous last words).
    }
}

impl Data {
    /// Create an empty data value.
    pub fn empty() -> Self {
        Self(Value::Null)
    }

    /// Check if the data value is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_null()
    }

    /// Try to cast to a value of a deserializable type (implementing
    /// `serde::de::DeserializeOwned`).
    pub fn value<T: DeserializeOwned>(&self) -> Result<T> {
        self.0
            .deserialized()
            .map_err(|e| anyhow!("deserialization error: {}", e))
    }

    /// Serialize to bytes.
    pub fn bytes(&self) -> Vec<u8> {
        util::write(&self).expect("serialization is expected to succeed")
    }

    pub fn try_from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(Self(util::read(bytes)?))
    }
}

impl<T> From<&T> for Data
where
    T: Serialize,
{
    fn from(value: &T) -> Self {
        Self(Value::serialized(value).expect("casting to a CBOR Value is expected to succeed"))
    }
}

impl Default for Data {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Data({})", format!("{:?}", &self.0))
    }
}

/// Special `App.tag` value for fungible tokens. See [`App`] for more details.
pub const TOKEN: char = 't';
/// Special `App.tag` value for non-fungible tokens (NFTs). See [`App`] for more details.
pub const NFT: char = 'n';

/// Check if the transaction is a simple transfer of assets specified by `app`.
pub fn is_simple_transfer(app: &App, tx: &Transaction) -> bool {
    match app.tag {
        TOKEN => token_amounts_balanced(app, tx),
        NFT => nft_state_preserved(app, tx),
        _ => false,
    }
}

/// Check if the provided app's token amounts are balanced in the transaction. This means that the
/// sum of the token amounts in the `tx` inputs is equal to the sum of the token amounts in the `tx`
/// outputs.
pub fn token_amounts_balanced(app: &App, tx: &Transaction) -> bool {
    match (
        sum_token_amount(app, tx.ins.iter().map(|(_, v)| v)),
        sum_token_amount(app, tx.outs.iter()),
    ) {
        (Ok(amount_in), Ok(amount_out)) => amount_in == amount_out,
        (..) => false,
    }
}

/// Check if the NFT states are preserved in the transaction. This means that the NFTs (created by
/// the provided `app`) in the `tx` inputs are the same as the NFTs in the `tx` outputs.
pub fn nft_state_preserved(app: &App, tx: &Transaction) -> bool {
    let nft_states_in = app_state_multiset(app, tx.ins.iter().map(|(_, v)| v));
    let nft_states_out = app_state_multiset(app, tx.outs.iter());

    nft_states_in == nft_states_out
}

/// Deprecated. Use [charm_values] instead.
#[deprecated(since = "0.7.0", note = "use `charm_values` instead")]
pub fn app_datas<'a>(
    app: &'a App,
    strings_of_charms: impl Iterator<Item = &'a Charms>,
) -> impl Iterator<Item = &'a Data> {
    charm_values(app, strings_of_charms)
}

/// Iterate over all charm values of a given app (charm key) in the given outputs
/// (strings of charms).
pub fn charm_values<'a>(
    app: &'a App,
    strings_of_charms: impl Iterator<Item = &'a Charms>,
) -> impl Iterator<Item = &'a Data> {
    strings_of_charms.filter_map(|charms| charms.get(app))
}

fn app_state_multiset<'a>(
    app: &App,
    strings_of_charms: impl Iterator<Item = &'a Charms>,
) -> BTreeMap<&'a Data, usize> {
    strings_of_charms
        .filter_map(|charms| charms.get(app))
        .fold(BTreeMap::new(), |mut r, s| {
            match r.get_mut(s) {
                Some(count) => *count += 1,
                None => {
                    r.insert(s, 1);
                }
            }
            r
        })
}

/// Sum the token amounts in the provided `strings_of_charms`.
pub fn sum_token_amount<'a>(
    app: &App,
    strings_of_charms: impl Iterator<Item = &'a Charms>,
) -> Result<u64> {
    ensure!(app.tag == TOKEN);
    strings_of_charms.fold(Ok(0u64), |amount, charms| match charms.get(app) {
        Some(state) => Ok(amount? + state.value::<u64>()?),
        None => amount,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;
    use proptest::prelude::*;
    use test_strategy::proptest;

    #[proptest]
    fn doesnt_crash(s: String) {
        let _ = TxId::from_str(&s);
    }

    #[proptest]
    fn txid_roundtrip(txid: TxId) {
        let s = txid.to_string();
        let txid2 = TxId::from_str(&s).unwrap();
        prop_assert_eq!(txid, txid2);
    }

    #[proptest]
    fn vk_serde_roundtrip(vk: B32) {
        let bytes = util::write(&vk).unwrap();
        let vk2 = util::read(bytes.as_slice()).unwrap();
        prop_assert_eq!(vk, vk2);
    }

    #[proptest]
    fn vk_serde_json_roundtrip(vk: App) {
        let json_str = serde_json::to_string(&vk).unwrap();
        // dbg!(&json_str);
        let vk2 = serde_json::from_str(&json_str).unwrap();
        prop_assert_eq!(vk, vk2);
    }

    #[proptest]
    fn vk_serde_yaml_roundtrip(vk: App) {
        let yaml_str = serde_yaml::to_string(&vk).unwrap();
        // dbg!(&yaml_str);
        let vk2 = serde_yaml::from_str(&yaml_str).unwrap();
        prop_assert_eq!(vk, vk2);
    }

    #[proptest]
    fn app_serde_roundtrip(app: App) {
        let bytes = util::write(&app).unwrap();
        let app2 = util::read(bytes.as_slice()).unwrap();
        prop_assert_eq!(app, app2);
    }

    #[proptest]
    fn utxo_id_serde_roundtrip(utxo_id: UtxoId) {
        let bytes = util::write(&utxo_id).unwrap();
        let utxo_id2 = util::read(bytes.as_slice()).unwrap();
        prop_assert_eq!(utxo_id, utxo_id2);
    }

    #[proptest]
    fn tx_id_serde_roundtrip(tx_id: TxId) {
        let bytes = util::write(&tx_id).unwrap();
        let tx_id2 = util::read(bytes.as_slice()).unwrap();
        prop_assert_eq!(tx_id, tx_id2);
    }

    #[test]
    fn minimal_txid() {
        let tx_id_bytes: [u8; 32] = [&[1u8], [0u8; 31].as_ref()].concat().try_into().unwrap();
        let tx_id = TxId(tx_id_bytes);
        let tx_id_str = tx_id.to_string();
        let tx_id_str_expected = "0000000000000000000000000000000000000000000000000000000000000001";
        assert_eq!(tx_id_str, tx_id_str_expected);
    }

    #[test]
    fn data_dbg() {
        let v = 42u64;
        let data: Data = Data::from(&v);
        assert_eq!(format!("{:?}", data), format!("Data({:?})", Value::from(v)));

        let data = Data::empty();
        assert_eq!(format!("{:?}", data), "Data(Null)");

        let vec1: Vec<u64> = vec![];
        let data: Data = Data::from(&vec1);
        assert_eq!(format!("{:?}", data), "Data(Array([]))");
    }

    #[test]
    fn data_bytes() {
        let v = ("42u64", 42u64);
        let data = Data::from(&v);
        let value = Value::serialized(&v).expect("serialization should have succeeded");

        let buf = util::write(&value).expect("serialization should have succeeded");

        assert_eq!(data.bytes(), buf);
    }

    #[test]
    fn dummy() {}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppInput {
    pub app_binaries: BTreeMap<B32, Vec<u8>>,
    pub app_private_inputs: BTreeMap<App, Data>,
}
