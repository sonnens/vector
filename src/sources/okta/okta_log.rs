use crate::codecs::DecodingConfig;
use crate::sources::util::http::HttpMethod;
use crate::sources::util::http_client::default_timeout;
use crate::{
    config::{GenerateConfig, SourceConfig, SourceContext, SourceOutput},
    http::Auth,
    serde::{default_decoding, default_framing_message_based},
    sources::{
        self,
        util::http_client::{
            build_url, call, default_interval, HttpClientBuilder, HttpClientContext,
            HttpClientInputs,
        },
    },
    tls::TlsSettings,
    Result,
};
use bytes::Bytes;
use futures_util::FutureExt;
use http::{response::Parts, Uri};
use serde_with::serde_as;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use vector_lib::configurable::configurable_component;
use vector_lib::shutdown::ShutdownSignal;
use vector_lib::{config::LogNamespace, event::Event};

fn find_rel_next_link(header: &str) -> Option<Uri> {
    let mut next = None;
    for part in header.split(',') {
        let relpart: Vec<_> = part.split(';').collect();
        if let Some(url) = relpart
            .get(0)
            .map(|s| s.trim().trim_matches(|c| c == '<' || c == '>'))
        {
            if url.starts_with("https://") {
                if part.contains("rel=\"next\"") {
                    next = Uri::try_from(url).ok();
                }
            }
        }
    }
    next
}

fn default_start_from_secs_ago() -> u64 {
    0
}

/// Configuration for the `okta_log` source.
#[serde_as]
#[configurable_component(source("okta_log", "Collect Okta System Logs."))]
#[derive(Clone, Debug)]
pub struct OktaLogPollConfig {
    /// Endpoints to scrape metrics from.
    #[configurable(metadata(docs::examples = "mydomain.okta.com"))]
    domain: String,

    /// The interval between scrapes. Requests are run concurrently so if a scrape takes longer
    /// than the interval a new scrape will be started. This can take extra resources, set the timeout
    /// to a value lower than the scrape interval to prevent this from happening.
    #[serde(default = "default_interval")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[serde(rename = "polling_interval_secs")]
    #[configurable(metadata(docs::human_name = "Polling Interval"))]
    interval: Duration,

    /// The start time for the first fetch.
    /// This is a duration in seconds from the current time.
    #[serde(default = "default_start_from_secs_ago")]
    #[configurable(metadata(docs::examples = "3600", default = "0"))]
    start_from_secs_ago: u64,

    #[configurable(derived)]
    #[configurable(metadata(docs::advanced))]
    token: String,
}

impl GenerateConfig for OktaLogPollConfig {
    fn generate_config() -> toml::Value {
        toml::Value::try_from(Self {
            domain: "mydomain.okta.com".to_string(),
            interval: default_interval(),
            start_from_secs_ago: 3600,
            token: "token".to_string(),
        })
        .unwrap()
    }
}

struct CheckpointHttpClientInput {
    url: std::sync::Arc<std::sync::RwLock<Uri>>,
    interval: Duration,
    timeout: Duration,
    headers: HashMap<String, Vec<String>>,
    content_type: String,
    tls: TlsSettings,
    proxy: vector_lib::config::proxy::ProxyConfig,
    shutdown: ShutdownSignal,
}

impl HttpClientInputs for CheckpointHttpClientInput {
    fn urls(&self) -> Vec<Uri> {
        if let Some(url) = self.url.read().ok() {
            return vec![url.clone()];
        } else {
            error!("could not acquire read lock reading checkpoint");
        }
        vec![]
    }

    fn interval(&self) -> &Duration {
        &self.interval
    }

    fn timeout(&self) -> &Duration {
        &self.timeout
    }

    fn headers(&self) -> &HashMap<String, Vec<String>> {
        &self.headers
    }

    fn content_type(&self) -> &String {
        &self.content_type
    }

    fn auth(&self) -> &Option<Auth> {
        &None
    }

    fn tls(&self) -> &TlsSettings {
        &self.tls
    }

    fn proxy(&self) -> &vector_lib::config::proxy::ProxyConfig {
        &self.proxy
    }

    fn shutdown(&self) -> &ShutdownSignal {
        &self.shutdown
    }
}

impl OktaLogPollConfig {
    pub fn get_decoding_config(&self) -> DecodingConfig {
        let decoding = default_decoding();
        let framing = default_framing_message_based();
        DecodingConfig::new(framing, decoding, false.into())
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "okta_log")]
impl SourceConfig for OktaLogPollConfig {
    async fn build(&self, cx: SourceContext) -> Result<sources::Source> {
        let ts = chrono::Utc::now().timestamp() as u64 - self.start_from_secs_ago;
        let ts = chrono::DateTime::from_timestamp(ts as i64, 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        let query = HashMap::from([("since".to_string(), vec![format!("{}", ts)])]);

        let url = Arc::new(RwLock::new(build_url(
            &format!("https://{}/api/v1/logs", self.domain).parse::<Uri>()?,
            &query,
        )));

        let tls = TlsSettings::default();

        let builder = OktaLogPollBuilder {
            checkpoint_url: url.clone(),
        };

        let inputs = CheckpointHttpClientInput {
            url: url.clone(),
            interval: self.interval,
            timeout: default_timeout(),
            headers: HashMap::from([
                ("accept".to_string(), vec!["application/json".to_string()]),
                (
                    "authorization".to_string(),
                    vec![format!("SSWS {}", self.token)],
                ),
            ]),
            content_type: "application/json".to_string(),
            tls,
            proxy: cx.proxy.clone(),
            shutdown: cx.shutdown,
        };

        Ok(call(inputs, builder, cx.out, HttpMethod::Get).boxed())
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        let schema_definition = default_decoding()
            .schema_definition(global_log_namespace)
            .with_standard_vector_source_metadata();

        vec![SourceOutput::new_maybe_logs(
            default_decoding().output_type(),
            schema_definition,
        )]
    }

    fn can_acknowledge(&self) -> bool {
        false
    }
}

#[derive(Clone)]
struct OktaLogPollBuilder {
    checkpoint_url: Arc<RwLock<Uri>>,
}

impl HttpClientBuilder for OktaLogPollBuilder {
    type Context = OktaLogPollContext;

    fn build(&self, _: &Uri) -> Self::Context {
        OktaLogPollContext {
            checkpoint: self.checkpoint_url.clone(),
        }
    }
}

struct OktaLogPollContext {
    checkpoint: std::sync::Arc<std::sync::RwLock<Uri>>,
}

impl OktaLogPollContext {
    fn decode_events(&mut self, buf: &Bytes) -> Vec<Event> {
        let mut events = Vec::new();
        let value = serde_json::from_slice::<serde_json::Value>(buf).unwrap();
        match value {
            serde_json::Value::Array(arr) => {
                for v in arr {
                    events.push(Event::from_json_value(v, LogNamespace::Legacy).unwrap());
                }
            }
            _ => { events.push(Event::from_json_value(value, LogNamespace::Legacy).unwrap()); }
        }
        events
    }
}

impl HttpClientContext for OktaLogPollContext {
    fn enrich_events(&mut self, events: &mut Vec<Event>) {
        let now = chrono::Utc::now();
        for event in events {
            match event {
                Event::Log(ref mut log) => {
                    LogNamespace::Legacy.insert_standard_vector_source_metadata(
                        log,
                        OktaLogPollConfig::NAME,
                        now,
                    );
                }
                _ => {}
            }
        }
    }

    fn on_response(&mut self, _: &Uri, headers: &Parts, body: &Bytes) -> Option<Vec<Event>> {
        let events = self.decode_events(&body);

        if events.len() > 0 {
            headers
                .headers
                .get_all("link")
                .into_iter()
                .filter_map(|link| link.to_str().ok())
                .filter_map(find_rel_next_link)
                .next()
                .map(|link| {
                    let _ = self.checkpoint.write().and_then(|mut checkpoint| {
                        *checkpoint = link;
                        Ok(())
                    })
                    .map_err(|e| error!("could not acquire write lock updating checkpoint: {}", e));
                });
            Some(events)
        } else {
            None
        }
    }

    fn on_http_response_error(&self, url: &Uri, header: &Parts) {
        if header.status == hyper::StatusCode::NOT_FOUND && url.path() == "/" {
            // https://github.com/vectordotdev/vector/pull/3801#issuecomment-700723178
            warn!(
                message = "I dunno",
                endpoint = %url,
            );
        }
    }
}
