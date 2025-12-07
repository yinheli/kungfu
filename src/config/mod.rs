mod dns_table;
mod hosts;
mod load;
pub mod setting;
pub use dns_table::{Addr, DnsTable};
pub use load::ArcSetting;
pub use load::load;
