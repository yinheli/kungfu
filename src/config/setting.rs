use serde::Deserialize;
use std::sync::OnceLock;
use url::Url;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Setting {
    pub bind: String,
    pub dns_port: u32,
    pub dns_upstream: Vec<String>,
    pub network: String,
    pub proxy: Vec<Proxy>,
    pub metrics: Option<String>,
}

impl Default for Setting {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0".to_string(),
            dns_port: 53,
            dns_upstream: vec![String::from("1.2.4.8"), String::from("8.8.8.8")],
            network: String::from("10.89.0.1/16"),
            proxy: Default::default(),
            metrics: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedProxyUrl {
    pub addr: String,
    pub has_auth: bool,
    pub username: String,
    pub password: Option<String>,
}

impl ParsedProxyUrl {
    pub fn parse(url: &str) -> Result<Self, url::ParseError> {
        let url = Url::parse(url)?;
        let host = url.host_str().unwrap_or("");
        let port = url.port().unwrap_or(1080);
        let username = url.username();
        Ok(Self {
            addr: format!("{host}:{port}"),
            has_auth: !username.is_empty(),
            username: username.to_string(),
            password: url.password().map(|s| s.to_string()),
        })
    }
}

#[derive(Default, Debug, Deserialize)]
pub struct Proxy {
    pub name: String,
    pub values: Vec<String>,
    #[serde(skip)]
    parsed: OnceLock<Vec<ParsedProxyUrl>>,
}

impl Proxy {
    pub fn parsed_values(&self) -> &[ParsedProxyUrl] {
        self.parsed.get_or_init(|| {
            self.values
                .iter()
                .filter_map(|url| ParsedProxyUrl::parse(url).ok())
                .collect()
        })
    }
}
