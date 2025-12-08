mod dns_table;
pub mod hosts;
mod load;
pub mod setting;
pub use dns_table::{Addr, DnsTable};
pub use hosts::Hosts;
pub use load::load;
