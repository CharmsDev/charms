//! Stub reqwest crate for ICP canister compatibility.
//! Provides type signatures only — no actual HTTP functionality.

use std::fmt;
use std::time::Duration;

pub use http::StatusCode;
pub use url::Url;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reqwest stub error: {}", self.0)
    }
}

impl std::error::Error for Error {}

pub mod header {
    pub use http::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
}

pub trait IntoUrl: sealed::IntoUrlSealed {}

mod sealed {
    pub trait IntoUrlSealed {
        fn into_url(self) -> std::result::Result<super::Url, super::Error>;
    }
}

impl IntoUrl for Url {}
impl sealed::IntoUrlSealed for Url {
    fn into_url(self) -> std::result::Result<Url, Error> {
        Ok(self)
    }
}

impl IntoUrl for &str {}
impl sealed::IntoUrlSealed for &str {
    fn into_url(self) -> std::result::Result<Url, Error> {
        Url::parse(self).map_err(|e| Error(e.to_string()))
    }
}

impl IntoUrl for &String {}
impl sealed::IntoUrlSealed for &String {
    fn into_url(self) -> std::result::Result<Url, Error> {
        Url::parse(self).map_err(|e| Error(e.to_string()))
    }
}

impl IntoUrl for String {}
impl sealed::IntoUrlSealed for String {
    fn into_url(self) -> std::result::Result<Url, Error> {
        Url::parse(&self).map_err(|e| Error(e.to_string()))
    }
}

impl IntoUrl for &Url {}
impl sealed::IntoUrlSealed for &Url {
    fn into_url(self) -> std::result::Result<Url, Error> {
        Ok(self.clone())
    }
}

#[derive(Debug, Clone)]
pub struct Client;

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder
    }

    pub fn get<U: IntoUrl>(&self, _url: U) -> RequestBuilder {
        RequestBuilder
    }

    pub fn post<U: IntoUrl>(&self, _url: U) -> RequestBuilder {
        RequestBuilder
    }
}

#[derive(Debug, Clone)]
pub struct ClientBuilder;

impl ClientBuilder {
    pub fn new() -> Self {
        ClientBuilder
    }

    pub fn build(self) -> Result<Client> {
        Ok(Client)
    }

    pub fn timeout(self, _timeout: Duration) -> Self {
        self
    }

    pub fn danger_accept_invalid_certs(self, _accept: bool) -> Self {
        self
    }

    pub fn proxy(self, _proxy: Proxy) -> Self {
        self
    }
}

#[derive(Debug, Clone)]
pub struct Proxy;

impl Proxy {
    pub fn all<U: IntoUrl>(_url: U) -> Result<Self> {
        Ok(Proxy)
    }

    pub fn https<U: IntoUrl>(_url: U) -> Result<Self> {
        Ok(Proxy)
    }
}

pub struct RequestBuilder;

impl RequestBuilder {
    pub fn header<K, V>(self, _key: K, _value: V) -> Self
    where
        K: TryInto<http::header::HeaderName>,
        V: TryInto<http::header::HeaderValue>,
    {
        self
    }

    pub fn headers(self, _headers: header::HeaderMap) -> Self {
        self
    }

    pub fn json<T: serde::Serialize + ?Sized>(self, _body: &T) -> Self {
        self
    }

    pub fn timeout(self, _timeout: Duration) -> Self {
        self
    }

    pub async fn send(self) -> std::result::Result<Response, Error> {
        Err(Error("reqwest stub: send not implemented".into()))
    }
}

pub struct Response {
    status: StatusCode,
    body: Vec<u8>,
}

impl Response {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub async fn text(self) -> Result<String> {
        String::from_utf8(self.body).map_err(|e| Error(e.to_string()))
    }

    pub async fn bytes(self) -> Result<bytes::Bytes> {
        Ok(bytes::Bytes::from(self.body))
    }

    pub async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T> {
        Err(Error("stub: json not implemented".into()))
    }

    pub fn headers(&self) -> &header::HeaderMap {
        static EMPTY: std::sync::LazyLock<header::HeaderMap> =
            std::sync::LazyLock::new(header::HeaderMap::new);
        &EMPTY
    }

    pub fn content_length(&self) -> Option<u64> {
        None
    }
}
