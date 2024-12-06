use crate::codecs::{DecodingConfig, Decoder};
use tokio_util::codec::Decoder as _;
use crate::sources::util::http::HttpMethod;
use vector_lib::schema::Definition;
use vrl::value::Kind;
use crate::vector_lib::event::EventContainer;
use crate::sources::util::http_client::default_timeout;
use crate::{
    config::{GenerateConfig, SourceConfig, SourceContext, SourceOutput},
    http::Auth,
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
use vector_lib::lookup::owned_value_path;

use vector_lib::codecs::{
    BytesDecoderConfig, JsonDeserializerConfig
};
use bytes::{Bytes, BytesMut};
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
    #[serde(default)]
    #[configurable(metadata(docs::examples = "3600", default = "0"))]
    start_from_secs_ago: u64,

    #[configurable(derived)]
    #[configurable(metadata(docs::human_name = "API Token"))]
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
    shutdown: ShutdownSignal
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
    pub fn get_decoding_config(&self, log_namespace: LogNamespace) -> DecodingConfig {
        DecodingConfig::new(
            BytesDecoderConfig::new().into(),
            JsonDeserializerConfig::default().into(),
            log_namespace,
        )
    }
    pub fn get_schema_definition(&self, decoding: DecodingConfig, log_namespace: LogNamespace) -> Definition {
        decoding.config()
        .schema_definition(log_namespace)
        .with_source_metadata(
            Self::NAME,
            None,
            &owned_value_path!("domain"),
            Kind::bytes(),
            None,
        )
        .with_standard_vector_source_metadata()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "okta_logs")]
impl SourceConfig for OktaLogPollConfig {
    async fn build(&self, cx: SourceContext) -> Result<sources::Source> {
        let log_namespace = cx.log_namespace(None);
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
            decoder: self.get_decoding_config(log_namespace).build()?,
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

    fn outputs(&self, log_namespace: LogNamespace) -> Vec<SourceOutput> {
        let decoding = self.get_decoding_config(log_namespace);
        vec![SourceOutput::new_maybe_logs(
            decoding.config().output_type(),
            self.get_schema_definition(decoding, log_namespace),
        )]
    }

    fn can_acknowledge(&self) -> bool {
        false
    }
}

#[derive(Clone)]
struct OktaLogPollBuilder {
    checkpoint_url: Arc<RwLock<Uri>>,
    decoder: Decoder,
}

impl HttpClientBuilder for OktaLogPollBuilder {
    type Context = OktaLogPollContext;

    fn build(&self, _: &Uri) -> Self::Context {
        OktaLogPollContext {
            checkpoint: self.checkpoint_url.clone(),
            decoder: self.decoder.clone(),
        }
    }
}

struct OktaLogPollContext {
    checkpoint: std::sync::Arc<std::sync::RwLock<Uri>>,
    decoder: Decoder,
}

impl OktaLogPollContext {
    fn decode_events(&mut self, buf: &mut BytesMut) -> Vec<Event> {
        if let Ok(Some(items)) = self.decoder.decode_eof(buf) {
            items.0.into_iter().map(|event| {
                event.into_events().collect::<Vec<_>>()
            }).flatten().collect::<Vec<_>>()
        } else {
            Vec::new()
        }
    }

}

impl HttpClientContext for OktaLogPollContext {
    fn enrich_events(&mut self, events: &mut Vec<Event>) {
        let now = chrono::Utc::now();
        for event in events {
            let log = event.as_mut_log();

            log.namespace().insert_standard_vector_source_metadata(log, OktaLogPollConfig::NAME, now);
        }
    }

    fn on_response(&mut self, _: &Uri, headers: &Parts, body: &Bytes) -> Option<Vec<Event>> {

        let mut buf = BytesMut::new();

        buf.extend_from_slice(body);

        let events = self.decode_events(&mut buf);

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

}
