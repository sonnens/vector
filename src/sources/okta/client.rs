//! Generalized HTTP client source.
//! Calls an endpoint at an interval, decoding the HTTP responses into events.
use bytes::BytesMut;
use chrono::Utc;
use futures::StreamExt as _;
use futures_util::{stream, FutureExt, TryFutureExt};
use serde_with::serde_as;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio_stream::wrappers::IntervalStream;
use tokio_util::codec::Decoder as _;
use vector_lib::codecs::JsonDeserializerConfig;
use vector_lib::config::proxy::ProxyConfig;
use vector_lib::json_size::JsonSize;
use vector_lib::shutdown::ShutdownSignal;

use crate::internal_events::{
    HttpClientEventsReceived, HttpClientHttpError, HttpClientHttpResponseError,
};
use crate::{
    codecs::{Decoder, DecodingConfig},
    config::{SourceConfig, SourceContext},
    sources,
    sources::util::http_client::{default_interval, default_timeout, warn_if_interval_too_low},
    tls::TlsSettings,
};
use vector_lib::codecs::{
    decoding::{DeserializerConfig, FramingConfig},
    StreamDecodingError,
};
use vector_lib::configurable::configurable_component;
use vector_lib::{
    config::{LogNamespace, SourceOutput},
    event::Event,
    EstimatedJsonEncodedSizeOf,
};

use crate::{
    http::HttpClient,
    internal_events::{EndpointBytesReceived, StreamClosedError}, //{
    //        EndpointBytesReceived, HttpClientEventsReceived, HttpClientHttpError,
    //        HttpClientHttpResponseError, StreamClosedError,
    //    },
    SourceSender,
};

use hyper::{Body, Request};
//use vector_lib::shutdown::ShutdownSignal;
//use vector_lib::{config::proxy::ProxyConfig, EstimatedJsonEncodedSizeOf};
//use vector_lib::EstimatedJsonEncodedSizeOf;

/// Configuration for the `okta` source.
#[serde_as]
#[configurable_component(source(
    "okta",
    "Pull observability data from an HTTP server at a configured interval."
))]
#[derive(Clone, Debug)]
pub struct OktaConfig {
    /// The HTTP endpoint to collect events from.
    ///
    /// The full path must be specified.
    #[configurable(metadata(docs::examples = "foo.okta.com"))]
    pub endpoint: String,

    /// token
    #[configurable(metadata(docs::examples = "00xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"))]
    pub token: String,

    /// The interval between scrapes. Requests are run concurrently so if a scrape takes longer
    /// than the interval a new scrape will be started. This can take extra resources, set the timeout
    /// to a value lower than the scrape interval to prevent this from happening.
    #[serde(default = "default_interval")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[serde(rename = "scrape_interval_secs")]
    #[configurable(metadata(docs::human_name = "Scrape Interval"))]
    pub interval: Duration,

    /// The timeout for each scrape request.
    #[serde(default = "default_timeout")]
    #[serde_as(as = "serde_with:: DurationSecondsWithFrac<f64>")]
    #[serde(rename = "scrape_timeout_secs")]
    #[configurable(metadata(docs::human_name = "Scrape Timeout"))]
    pub timeout: Duration,

    /// The timeout for each scrape request.
    #[serde(rename = "since")]
    #[configurable(metadata(docs::human_name = "Since"))]
    pub since: Option<String>,

    /// The namespace to use for logs. This overrides the global setting.
    #[configurable(metadata(docs::hidden))]
    #[serde(default)]
    pub log_namespace: Option<bool>,
}

impl Default for OktaConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:9898/logs".to_string(),
            token: "".to_string(),
            interval: default_interval(),
            timeout: default_timeout(),
            since: None,
            log_namespace: None,
        }
    }
}

impl_generate_config_from_default!(OktaConfig);

fn find_rel_next_link(header: &str) -> Option<String> {
    for part in header.split(',') {
        let relpart: Vec<_> = part.split(';').collect();
        if let Some(url) = relpart
            .get(0)
            .map(|s| s.trim().trim_matches(|c| c == '<' || c == '>'))
        {
            if url.starts_with("https://") {
                if part.contains("rel=\"next\"") {
                    return Some(url.to_string());
                }
            }
        }
    }
    None
}

#[async_trait::async_trait]
#[typetag::serde(name = "okta")]
impl SourceConfig for OktaConfig {
    async fn build(&self, cx: SourceContext) -> crate::Result<sources::Source> {
        // build the url
        let endpoint = Arc::new(Mutex::new(self.endpoint.clone()));

        let tls = TlsSettings::default();

        let log_namespace = cx.log_namespace(self.log_namespace);

        warn_if_interval_too_low(self.timeout, self.interval);

        Ok(giver(
            endpoint,
            tls,
            cx.proxy.clone(),
            self.token.clone(),
            self.interval.clone(),
            self.timeout.clone(),
            log_namespace,
            cx.shutdown,
            cx.out,
        )
        .boxed())
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        // There is a global and per-source `log_namespace` config. The source config overrides the global setting,
        // and is merged here.
        let log_namespace = global_log_namespace.merge(self.log_namespace);

        vec![SourceOutput::new_maybe_logs(
            JsonDeserializerConfig::default().output_type(),
            JsonDeserializerConfig::default().schema_definition(log_namespace.clone()),
        )]
    }

    fn can_acknowledge(&self) -> bool {
        false
    }
}

fn enrich_events(events: &mut Vec<Event>, log_namespace: &LogNamespace) {
    let now = Utc::now();
    for event in events {
        log_namespace.insert_standard_vector_source_metadata(
            event.as_mut_log(),
            OktaConfig::NAME,
            now,
        );
    }
}

/// Calls one or more urls at an interval.
///   - The HTTP request is built per the options in provided generic inputs.
///   - The HTTP response is decoded/parsed into events by the specific context.
///   - The events are then sent to the output stream.
pub(crate) async fn giver(
    url: Arc<Mutex<String>>,
    tls: TlsSettings,
    proxy: ProxyConfig,
    token: String,
    interval: Duration,
    timeout: Duration,
    log_namespace: LogNamespace,
    shutdown: ShutdownSignal,
    mut out: SourceSender,
) -> Result<(), ()> {
    // Build the decoder.
    let decoder = DecodingConfig::new(
        FramingConfig::Bytes,
        DeserializerConfig::Json(JsonDeserializerConfig::default()),
        log_namespace.clone(),
    )
    .build()
    .unwrap();
    let client = HttpClient::new(tls.clone(), &proxy).expect("Building HTTP client failed");
    let mut stream = IntervalStream::new(tokio::time::interval(interval))
        .take_until(shutdown)
        .then(move |_| {
            let client = client.clone();
            let timeout = timeout.clone();
            let url = url.clone();
            let token = token.clone();
            let decoder = decoder.clone();

            async move {
                // Make sure the unfold closure also uses `move`:
                stream::unfold((), move |_| {
                    let timeout = timeout.clone();
                    let url = url.clone();
                    let token = token.clone();
                    let log_namespace = log_namespace.clone();
                    let decoder = decoder.clone();
                    let client = client.clone();
                    async move {
                        let this_url = url.lock().await.clone();

                        let mut request = Request::get(&this_url)
                            .body(Body::empty())
                            .expect("error creating request");

                        let headers = request.headers_mut();
                        headers.insert(
                            http::header::AUTHORIZATION,
                            format!("SSWS {}", token).parse().unwrap(),
                        );
                        headers.insert(http::header::ACCEPT, "application/json".parse().unwrap());
                        headers.insert(
                            http::header::CONTENT_TYPE,
                            "application/json".parse().unwrap(),
                        );

                        // Note: clone client if needed.
                        let client = client.clone();
                        let timeout = timeout.clone();
                        let decoder = decoder.clone();
                        let this_url = this_url.clone();
                        let this_url_for_error = this_url.clone();
                        let url = url.clone();

                        tokio::time::timeout(timeout.clone(), client.send(request))
                            .then(move |result| async move {
                                match result {
                                    Ok(Ok(response)) => Ok(response),
                                    Ok(Err(error)) => Err(error.into()),
                                    Err(_) => Err(format!(
                                        "Timeout error: request exceeded {}s",
                                        timeout.as_secs_f64()
                                    )
                                    .into()),
                                }
                            })
                            // Mark the closure as move to capture the necessary variables.
                            .and_then(move |response| async move {
                                let (header, body) = response.into_parts();
                                let body = hyper::body::to_bytes(body).await?;
                                emit!(EndpointBytesReceived {
                                    byte_size: body.len(),
                                    protocol: "http",
                                    endpoint: this_url.clone().as_str(),
                                });
                                Ok((header, body))
                            })
                            // Again, mark this closure as move.
                            .then(move |response| {
                                let decoder = decoder.clone();
                                async move {
                                    match response {
                                        Ok((header, body))
                                            if header.status == hyper::StatusCode::OK =>
                                        {
                                            let mut buf = BytesMut::new();
                                            buf.extend_from_slice(&body);
                                            let mut events = decode_events(&mut buf, decoder);
                                            let byte_size = if events.is_empty() {
                                                JsonSize::zero()
                                            } else {
                                                events.estimated_json_encoded_size_of()
                                            };

                                            emit!(HttpClientEventsReceived {
                                                byte_size,
                                                count: events.len(),
                                                url: this_url_for_error.clone()
                                            });

                                            if events.is_empty() {
                                                return None;
                                            }
                                            if let Some(next) = header
                                                .headers
                                                .get_all("link")
                                                .iter()
                                                .filter_map(|v| v.to_str().ok())
                                                .filter_map(|v| find_rel_next_link(v))
                                                .next()
                                            {
                                                let mut endpoint = url.lock().await;
                                                *endpoint = next;
                                                drop(endpoint);
                                            };
                                            enrich_events(&mut events, &log_namespace);
                                            Some((stream::iter(events), ()))
                                        }
                                        Ok((header, _)) => {
                                            emit!(HttpClientHttpResponseError {
                                                code: header.status,
                                                url: this_url_for_error.to_string(),
                                            });
                                            None
                                        }
                                        Err(error) => {
                                            emit!(HttpClientHttpError {
                                                error,
                                                url: this_url_for_error.to_string()
                                            });
                                            None
                                        }
                                    }
                                }
                            })
                            .await
                    }
                })
                .flatten()
                .boxed()
            }
        })
        .flatten_unordered(None)
        .boxed();

    match out.send_event_stream(&mut stream).await {
        Ok(()) => {
            debug!("Finished sending.");
            Ok(())
        }
        Err(_) => {
            let (count, _) = stream.size_hint();
            emit!(StreamClosedError { count });
            Err(().into())
        }
    }
}

fn decode_events(buf: &mut BytesMut, mut decoder: Decoder) -> Vec<Event> {
    let mut events = Vec::new();
    loop {
        match decoder.decode_eof(buf) {
            Ok(Some((next, _))) => {
                events.extend(next);
            }
            Ok(None) => break,
            Err(error) => {
                // Error is logged by `crate::codecs::Decoder`, no further
                // handling is needed here.
                if !error.can_continue() {
                    break;
                }
                break;
            }
        }
    }
    events
}
