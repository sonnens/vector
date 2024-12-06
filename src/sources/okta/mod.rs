#[cfg(feature = "sources-okta_logs")]
mod okta_logs;

#[cfg(feature = "sources-okta_logs")]
pub use okta_logs::OktaLogPollConfig;
