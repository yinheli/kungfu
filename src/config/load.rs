use super::hosts::Hosts;
use super::setting::Setting;
use crate::rule::{RuleConfig, Rules};
use crate::runtime::{ArcRuntime, RuntimeContext};
use crate::{cli::Cli, config::DnsTable};
use anyhow::{Error, bail};
use ipnet::IpNet;
use log::{debug, error, info};
use notify::RecursiveMode;
use notify_debouncer_mini::Debouncer;
use parking_lot::{Mutex, RwLock};
use std::ffi::OsStr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{fs, path::PathBuf};

// holder notify watchers
static WATCHERS: Mutex<Vec<Debouncer<notify::RecommendedWatcher>>> = Mutex::new(vec![]);

pub fn load(cli: &Cli) -> Result<ArcRuntime, Error> {
    let path = config_path(&cli.config);
    let setting = load_settings(&path)?;

    // load config.d
    let mut config_dir = PathBuf::from(path.parent().unwrap());
    config_dir.push("config.d");

    let rule_configs = load_all_rule_configs(config_dir.clone())?;

    let mut host_file = config_dir.clone();
    host_file.push("hosts");
    let hosts = load_hosts_file(host_file)?;

    // test settings
    test_setting(&setting)?;

    // build runtime components
    let rules = Arc::new(Rules::new(rule_configs)?);
    let dns_table = DnsTable::new(&setting.network);

    let runtime = Arc::new(RuntimeContext {
        setting: Arc::new(setting),
        rules,
        hosts: RwLock::new(hosts),
        dns_table,
    });

    // watch rules
    if !cli.test && !cli.disable_watch {
        watch(runtime.clone(), config_dir);
    }

    Ok(runtime)
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
    let setting: Setting = serde_yaml::from_str(fs::read_to_string(path).unwrap().as_str())?;

    Ok(setting)
}

fn load_hosts_file(host_file: PathBuf) -> Result<Hosts, Error> {
    let hosts_content = if host_file.is_file() && host_file.exists() {
        debug!("load host file: {:?}", host_file);
        fs::read_to_string(host_file)?
    } else {
        debug!("load host file not exists: {:?}", host_file);
        "".to_string()
    };

    Hosts::parse(&hosts_content)
}

fn load_all_rule_configs(rules_dir: PathBuf) -> Result<Vec<RuleConfig>, Error> {
    if !rules_dir.exists() {
        return Ok(vec![]);
    }

    let mut configs = vec![];

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
                        let cs = load_rule_config_file(item.unwrap().path())?;
                        if let Some(mut cs) = cs {
                            configs.append(&mut cs);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(configs)
}

fn load_rule_config_file(rule_file: PathBuf) -> Result<Option<Vec<RuleConfig>>, Error> {
    debug!("load rule file: {:?}", &rule_file);
    let configs: Option<Vec<RuleConfig>> =
        serde_yaml::from_str(fs::read_to_string(rule_file).unwrap().as_str()).unwrap();

    Ok(configs)
}

fn watch(runtime: ArcRuntime, rules_dir: PathBuf) {
    debug!("watch dir: {:?}", &rules_dir);

    let dir = rules_dir.clone();

    let event_handler = move |event: notify_debouncer_mini::DebounceEventResult| {
        if let Ok(evs) = event {
            evs.iter().for_each(|v| {
                if v.path.file_name().eq(&Some(OsStr::new("hosts"))) {
                    info!("reload hosts: {:?}", v.path);
                    if let Err(e) = reload_hosts(&runtime, v.path.clone()) {
                        error!("load hosts error: {:?}", e);
                    }
                }
            });

            let has_rule_changes = evs.iter().any(|v| {
                let ext = v.path.extension();
                if let Some(v) = ext {
                    return v == "yaml" || v == "yml";
                }
                false
            });

            if has_rule_changes {
                info!("reload rules");
                if let Err(e) = reload_rules(&runtime, rules_dir.clone()) {
                    error!("load rules error: {:?}", e);
                }
            }
        }
    };

    let timeout = Duration::from_secs(2);
    let mut deboncer = notify_debouncer_mini::new_debouncer(timeout, event_handler).unwrap();

    let w = deboncer.watcher();
    w.watch(dir.as_path(), RecursiveMode::NonRecursive).unwrap();
    WATCHERS.lock().push(deboncer);
}

fn reload_hosts(runtime: &RuntimeContext, host_file: PathBuf) -> Result<(), Error> {
    let hosts = load_hosts_file(host_file)?;
    *runtime.hosts.write() = hosts;
    runtime.dns_table.clear();
    Ok(())
}

fn reload_rules(runtime: &RuntimeContext, rules_dir: PathBuf) -> Result<(), Error> {
    let configs = load_all_rule_configs(rules_dir)?;
    runtime.rules.reload(configs)?;
    runtime.dns_table.clear();
    Ok(())
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

        let runtime = do_load("config/config.yaml");
        let runtime2 = do_load("config/config.yml");

        assert_eq!(runtime.setting.bind, runtime2.setting.bind);
        assert_eq!(runtime.setting.dns_port, runtime2.setting.dns_port);
        assert_eq!(runtime.setting.network, runtime2.setting.network);

        assert_eq!(runtime.setting.bind, "0.0.0.0".to_string());
        assert_eq!(runtime.setting.dns_port, 53);
        assert_eq!(runtime.setting.network, "10.89.0.1/16".to_string());
    }
}
