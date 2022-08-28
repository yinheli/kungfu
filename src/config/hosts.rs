use anyhow::Error;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

#[derive(Debug, Default)]
pub struct Hosts(Vec<(String, glob::Pattern)>);

impl Hosts {
    pub fn parse(hosts: &str) -> Result<Self, Error> {
        let mut items = vec![];
        for line in hosts.lines() {
            let mut line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(v) = line.find('#') {
                line = &line[..v];
            }

            let item = line.splitn(2, ' ').map(|v| v.trim()).collect::<Vec<_>>();
            if item.len() != 2 {
                continue;
            }

            let target = item[0].to_string();
            let pattern = glob::Pattern::new(item[1])?;

            items.push((target, pattern));
        }
        Ok(Self(items))
    }

    pub fn match_domain(&self, domain: &str) -> Option<String> {
        self.0.par_iter().find_map_first(|v| {
            if v.1.matches(domain) {
                return Some(v.0.to_string());
            }
            None
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let s = r"
        # like /etc/hosts but add CNAME support
        192.168.1.20                  my-app.com       # this is end line comment
        cdn.my-app.com.a.bdydns.com.  cdn.my-app.com
        
        192.168.8.20                  *-dev.app.com    # glob express
        ";

        let hosts = Hosts::parse(s);
        assert!(hosts.is_ok());
    }

    #[test]
    fn match_domain() {
        let s = r"
        127.0.0.1        localhost
        192.168.8.20     *-dev.app.com # glob express
        ";
        let hosts = Hosts::parse(s);
        assert!(hosts.is_ok());
        let hosts = hosts.unwrap();

        let r = hosts.match_domain("localhost");
        assert!(r.is_some());
        assert_eq!(r, Some("127.0.0.1".to_string()));

        let r = hosts.match_domain("test-dev.app.com");
        assert!(r.is_some());
        assert_eq!(r, Some("192.168.8.20".to_string()));

        let r = hosts.match_domain("google.com");
        assert!(r.is_none());
    }
}
