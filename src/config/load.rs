use super::hosts::Hosts;
use super::setting::{Rule, Setting};
use crate::{cli::Cli, config::DnsTable};
use anyhow::{bail, Error};
use ipnet::IpNet;
use log::{debug, error, info};
use notify::RecursiveMode;
use notify_debouncer_mini::Debouncer;
use std::ffi::OsStr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

pub type ArcSetting = Arc<Setting>;

// holder notify watchers
static WATCHERS: Mutex<Vec<Debouncer<notify::RecommendedWatcher>>> = Mutex::new(vec![]);

pub fn load(cli: &Cli) -> Result<ArcSetting, Error> {
    let path = config_path(&cli.config);
    let mut setting = load_settings(&path)?;

    // load config.d
    let mut config_dir = PathBuf::from(path.parent().unwrap());
    config_dir.push("config.d");
    load_all_rules(&setting, config_dir.clone())?;

    let mut host_file = config_dir.clone();
    host_file.push("hosts");
    load_hosts(&setting, host_file)?;

    // test settings
    test_setting(&setting)?;

    // dns table
    setting.dns_table = DnsTable::new(&setting.network);

    let setting = Arc::new(setting);

    // watch rules
    if !cli.test && !cli.disable_watch {
        watch(setting.clone(), config_dir);
    }

    Ok(setting)
}

fn config_path(file: &str) -> PathBuf {
    let mut path = PathBuf::from(file);
    if !path.exists() {
        info!("file not found, will try check for alternative extension");
        if let Some(ext) = path.extension() {
            match ext.to_str().unwrap() {
                "yaml" => {
                    path.set_extension("yml");
                }
                "yml" => {
                    path.set_extension("yaml");
                }
                _ => {}
            }
        }
    }
    path
}

fn load_settings(path: &PathBuf) -> Result<Setting, Error> {
    let setting: Setting =
        serde_yaml::from_str(fs::read_to_string(path).unwrap().as_str())?;

    Ok(setting)
}

fn load_hosts(setting: &Setting, host_file: PathBuf) -> Result<(), Error> {
    let hosts = if host_file.is_file() && host_file.exists() {
        debug!("load host file: {:?}", host_file);
        fs::read_to_string(host_file)?
    } else {
        debug!("load host file not exists: {:?}", host_file);
        "".to_string()
    };

    *setting.hosts.write().unwrap() = hosts;
    *setting.hosts_match.write().unwrap() = Hosts::parse(&setting.hosts.read().unwrap()).unwrap();
    setting.dns_table.clear();

    Ok(())
}

fn load_all_rules(setting: &Setting, rules_dir: PathBuf) -> Result<(), Error> {
    if !rules_dir.exists() {
        return Ok(());
    }

    let mut rules = vec![];

    for item in fs::read_dir(rules_dir).unwrap() {
        if let Ok(ref it) = item {
            if !it.file_type().unwrap().is_file() {
                continue;
            }

            if let Some(ext) = it.path().extension() {
                let ext = ext.to_str().unwrap().to_lowercase();
                let ext = ext.as_str();
                match ext {
                    "yaml" | "yml" => {
                        let rs = load_rule_file(item.unwrap().path())?;
                        if let Some(mut rs) = rs {
                            rules.append(&mut rs);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    *setting.rules.write().unwrap() = rules;
    setting.dns_table.clear();

    Ok(())
}

fn load_rule_file(rule_file: PathBuf) -> Result<Option<Vec<Rule>>, Error> {
    debug!("load rule file: {:?}", &rule_file);
    let rules: Option<Vec<Rule>> =
        serde_yaml::from_str(fs::read_to_string(rule_file).unwrap().as_str()).unwrap();

    Ok(rules)
}

fn watch(setting: ArcSetting, rules_dir: PathBuf) {
    debug!("watch dir: {:?}", &rules_dir);

    let dir = rules_dir.clone();

    let event_handler = move |event: notify_debouncer_mini::DebounceEventResult| {
        if let Err(e) = load_all_rules(&setting.clone(), rules_dir.clone()) {
            error!("load rules error: {:?}", e);
        }

        if let Ok(evs) = event {
            evs.iter().for_each(|v| {
                if v.path.file_name().eq(&Some(OsStr::new("hosts"))) {
                    info!("reload hosts: {:?}", v.path);
                    if let Err(e) = load_hosts(&setting.clone(), v.path.clone()) {
                        error!("load hosts error: {:?}", e);
                    }
                }
            });

            let rules = evs.iter().any(|v| {
                let ext = v.path.extension();
                if let Some(v) = ext {
                    return v == "yaml" || v == "yml";
                }
                false
            });

            if rules {
                info!("reload rules");
                if let Err(e) = load_all_rules(&setting.clone(), rules_dir.clone()) {
                    error!("load rules error: {:?}", e);
                }
            }
        }
    };

    let timeout = Duration::from_secs(2);
    let mut deboncer = notify_debouncer_mini::new_debouncer(timeout, event_handler).unwrap();

    let w = deboncer.watcher();
    w.watch(dir.as_path(), RecursiveMode::NonRecursive).unwrap();
    WATCHERS.lock().unwrap().push(deboncer);
}

fn test_setting(setting: &Setting) -> Result<(), Error> {
    assert!((0u32..=0xffff).contains(&setting.dns_port));

    let network = IpNet::from_str(&setting.network);
    assert!(network.is_ok());
    assert!(network.unwrap().hosts().count() > 1022);

    if !setting.proxy.is_empty() {
        for p in setting.proxy.iter() {
            if p.values.iter().any(|v| !v.starts_with("socks5://")) {
                bail!("proxy only support socks5");
            }
        }
    }

    assert!(!setting.dns_upstream.is_empty());

    if setting.metrics.is_some() {
        let addr = setting.metrics.clone();
        if SocketAddr::from_str(&addr.unwrap()).is_err() {
            bail!("metrics is invalid");
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {

    use super::*;

    #[tokio::test]
    async fn config_load() {
        let do_load = |file: &str| {
            load(&Cli {
                config: file.to_string(),
                test: false,
                disable_watch: false,
                verbose: true,
            })
            .unwrap()
        };

        let config = do_load("config/config.yaml");
        let config2 = do_load("config/config.yml");

        assert_eq!(config.bind, config2.bind);
        assert_eq!(config.dns_port, config2.dns_port);
        assert_eq!(config.network, config2.network);

        assert_eq!(config.bind, "0.0.0.0".to_string());
        assert_eq!(config.dns_port, 53);
        assert_eq!(config.network, "10.89.0.1/16".to_string());
    }
}
