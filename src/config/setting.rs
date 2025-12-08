use serde::Deserialize;

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

#[derive(Default, Debug, Deserialize)]
pub struct Proxy {
    pub name: String,
    pub values: Vec<String>,
}
