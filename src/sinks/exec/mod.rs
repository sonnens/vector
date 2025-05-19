use crate::{
    codecs::{EncodingConfigWithFraming, SinkType},
    internal_events::ExecFailedError,
    sinks::prelude::*,
};
use bytes::BytesMut;
use futures::TryFutureExt;
use serde_with::serde_as;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::{io::AsyncWriteExt, process::Command, sync::Mutex};
use tokio_util::codec::Encoder as _;
use vector_lib::codecs::{
    encoding::{Framer, FramingConfig},
    TextSerializerConfig,
};

use std::process::Stdio;

/// Mode of operation for running the command.
#[configurable_component]
#[derive(Clone, Copy, Debug)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Mode {
    /// The command is run once per event.
    Once,

    /// The command is run until it exits, potentially being restarted.
    Streaming,
}

/// Mode of operation for running the command.
#[configurable_component]
#[derive(Clone, Copy, Debug)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OnceMode {
    /// Pass log events as positional argument
    Argument,
    /// Pass the event to stdin, EOF terminated
    Pipe,
}

impl Default for OnceMode {
    fn default() -> Self {
        OnceMode::Argument
    }
}

const fn default_exec_timeout_milliseconds() -> u64 {
    5
}
const fn default_respawn_on_exit() -> bool {
    false
}
const fn default_respawn_interval_secs() -> u64 {
    5
}

const fn default_max_concurrent_processes() -> u64 {
    1
}

const fn default_clear_environment() -> bool {
    false
}

fn environment_examples() -> HashMap<String, String> {
    HashMap::<_, _>::from_iter([
        ("LANG".to_owned(), "es_ES.UTF-8".to_owned()),
        ("TZ".to_owned(), "Etc/UTC".to_owned()),
        ("PATH".to_owned(), "/bin:/usr/bin:/usr/local/bin".to_owned()),
    ])
}

/// Configuration options for scheduled commands.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct OnceConfig {
    /// the mode of operation for the command.
    #[serde(default)]
    #[configurable(metadata(docs::human_name = "Mode"))]
    mode: OnceMode,

    /// The maximum amount of time, in seconds, to wait for the command to finish.
    ///
    /// If the command takes longer than `exec_timeout_secs` to run, it is killed.
    #[serde(default = "default_exec_timeout_milliseconds")]
    #[configurable(metadata(docs::human_name = "Timeout"))]
    exec_timeout_milliseconds: u64,

    /// The maximum number of processes to spawn.
    ///
    /// each event will spawn a new process, up to this limit.
    #[serde(default = "default_max_concurrent_processes")]
    #[configurable(metadata(docs::human_name = "Max Processes"))]
    max_concurrent_processes: u64,
}

impl Default for OnceConfig {
    fn default() -> Self {
        Self {
            exec_timeout_milliseconds: default_exec_timeout_milliseconds(),
            max_concurrent_processes: default_max_concurrent_processes(),
            mode: OnceMode::default(),
        }
    }
}

/// Configuration options for streaming commands.
/// events are passed to the command via stdin
#[configurable_component]
#[derive(Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct StreamingConfig {
    /// Whether or not the command should be rerun if the command exits.
    #[serde(default = "default_respawn_on_exit")]
    respawn_on_exit: bool,

    /// The amount of time, in seconds, before rerunning a streaming command that exited.
    #[serde(default = "default_respawn_interval_secs")]
    #[configurable(metadata(docs::human_name = "Respawn Interval"))]
    respawn_interval_secs: u64,
}

/// Configuration for the `exec` sink.
#[serde_as]
#[configurable_component(sink("exec", "Output observability events into a command."))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ExecSinkConfig {
    /// The command to run, plus any arguments required.
    #[configurable(metadata(docs::examples = "echo"))]
    pub command: Vec<String>,

    #[configurable(derived)]
    pub mode: Mode,

    #[configurable(derived)]
    pub once: Option<OnceConfig>,

    #[configurable(derived)]
    pub streaming: Option<StreamingConfig>,

    /// The directory in which to run the command.
    pub working_directory: Option<PathBuf>,

    /// Custom environment variables to set or update when running the command.
    /// If a variable name already exists in the environment, its value is replaced.
    #[serde(default)]
    #[configurable(metadata(docs::additional_props_description = "An environment variable."))]
    #[configurable(metadata(docs::examples = "environment_examples()"))]
    pub environment: Option<HashMap<String, String>>,

    /// Whether or not to clear the environment before setting custom environment variables.
    #[serde(default = "default_clear_environment")]
    pub clear_environment: bool,

    #[serde(flatten)]
    pub encoding: EncodingConfigWithFraming,

    #[configurable(derived)]
    #[serde(
        default,
        deserialize_with = "crate::serde::bool_or_struct",
        skip_serializing_if = "crate::serde::is_default"
    )]
    pub acknowledgements: AcknowledgementsConfig,

    /// The namespace to use for logs. This overrides the global setting.
    #[configurable(metadata(docs::hidden))]
    #[serde(default)]
    log_namespace: Option<bool>,
}

impl GenerateConfig for ExecSinkConfig {
    fn generate_config() -> toml::Value {
        toml::Value::try_from(Self {
            command: Default::default(),
            mode: Mode::Once,
            once: None,
            streaming: None,
            working_directory: None,
            environment: None,
            clear_environment: default_clear_environment(),
            encoding: (None::<FramingConfig>, TextSerializerConfig::default()).into(),
            acknowledgements: AcknowledgementsConfig::default(),
            log_namespace: None,
        })
        .unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "exec")]
impl SinkConfig for ExecSinkConfig {
    async fn build(
        &self,
        cx: SinkContext,
    ) -> crate::Result<(super::VectorSink, super::Healthcheck)> {
        let sink = ExecSink::new(self, cx)?;
        Ok((
            super::VectorSink::from_event_streamsink(sink),
            future::ok(()).boxed(),
        ))
    }

    fn input(&self) -> Input {
        Input::new(self.encoding.config().1.input_type())
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements
    }
}

pub struct ExecSink {
    command: Vec<String>,
    transformer: Transformer,
    encoder: Encoder<Framer>,
    working_directory: Option<PathBuf>,
    environment: Option<HashMap<String, String>>,
    clear_environment: bool,
    mode: Mode,
    once_config: OnceConfig,
    child_semaphore: Arc<tokio::sync::Semaphore>,
    #[allow(dead_code)]
    streaming_config: StreamingConfig,
}

impl ExecSink {
    pub fn new(config: &ExecSinkConfig, _cx: SinkContext) -> crate::Result<Self> {
        let transformer = config.encoding.transformer();
        let (framer, serializer) = config.encoding.build(SinkType::StreamBased)?;
        let encoder = Encoder::<Framer>::new(framer, serializer);

        Ok(Self {
            command: config.command.clone(),
            transformer,
            encoder,
            working_directory: config.working_directory.clone(),
            environment: config.environment.clone(),
            clear_environment: config.clear_environment,
            mode: config.mode,
            child_semaphore: Arc::new(tokio::sync::Semaphore::new(
                config
                    .once
                    .as_ref()
                    .map_or(1, |c| c.max_concurrent_processes as usize),
            )),
            once_config: config.once.clone().unwrap_or_default(),
            streaming_config: config.streaming.clone().unwrap_or_default(),
        })
    }

    fn build_command(&self) -> Command {
        let mut cmd = Command::new(&self.command[0]);

        if self.command.len() > 1 {
            cmd.args(&self.command[1..]);
        }

        if self.clear_environment {
            cmd.env_clear();
        }

        if let Some(envs) = &self.environment {
            cmd.envs(envs);
        }

        if let Some(dir) = &self.working_directory {
            cmd.current_dir(dir);
        }

        cmd.kill_on_drop(true);

        cmd
    }

    async fn run_once(&mut self, mut event: Event) -> Result<(), ()> {
        let mut encoded = BytesMut::new();
        self.transformer.transform(&mut event);
        self.encoder.encode(event, &mut encoded).unwrap();

        let mut cmd = match self.once_config.mode {
            OnceMode::Argument => {
                let mut cmd = self.build_command();
                cmd.arg(String::from_utf8_lossy(&encoded).to_string());
                cmd.stdin(Stdio::null());
                cmd
            }
            OnceMode::Pipe => {
                let mut cmd = self.build_command();
                cmd.stdin(Stdio::piped());
                cmd
            }
        };
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());

        let mut child = cmd.spawn().map_err(|e| {
            emit!(ExecFailedError {
                command: self.command.join(" ").as_str(),
                error: e,
            });
        })?;

        if let OnceMode::Pipe = self.once_config.mode {
            let stdin = child.stdin.as_mut().ok_or_else(|| {
                emit!(ExecFailedError {
                    command: self.command.join(" ").as_str(),
                    error: std::io::Error::new(std::io::ErrorKind::Other, "Failed to get stdin",),
                });
            })?;

            stdin.write_all(&encoded).await.map_err(|e| {
                emit!(ExecFailedError {
                    command: self.command.join(" ").as_str(),
                    error: e,
                });
            })?;
        }

        cmd.status()
            .await
            .and_then(|r| {
                if r.success() {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "command failed",
                    ))
                }
            })
            .map_err(|e| {
                emit!(ExecFailedError {
                    command: self.command.join(" ").as_str(),
                    error: e,
                });
            })?;
        Ok(())
    }

    async fn run_streaming(&mut self, input: BoxStream<'_, Event>) -> Result<(), ()> {
        let mut cmd = self.build_command();
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());

        let mut child = cmd
            .spawn()
            .map_err(|e| {
                emit!(ExecFailedError {
                    command: self.command.join(" ").as_str(),
                    error: e,
                });
            })?;

        let stdin = Arc::new(Mutex::new(child.stdin.take().ok_or_else(|| {})?));
        let transformer = self.transformer.clone();

        let command = Arc::new(self.command.join(" ").to_string());

        input
        .take_while(|_| async { child.id().is_some() })
        .for_each(|mut event| {
            let stdin = stdin.clone();
            let command = command.clone();

            let finalizers = event.take_finalizers();

            transformer.transform(&mut event);
            let mut encoded = BytesMut::new();
            let encode_result = self.encoder.encode(event, &mut encoded).map_err(|e| {
                emit!(ExecFailedError {
                    command: command.as_str(),
                    error: std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to encode event: {}", e),
                    ),
                });
                finalizers.update_status(EventStatus::Errored);
            });

            async move {
                if let Err(_) = encode_result {
                    return;
                }
                let mut stdin = stdin.lock().await;
                if let Err(e) = stdin.write_all(&encoded).await.map(|_| {
                    finalizers.update_status(EventStatus::Delivered);
                }) {
                    emit!(ExecFailedError {
                        command: command.as_str(),
                        error: e.into(),
                    });
                    finalizers.update_status(EventStatus::Errored);
                };
            }
        })
        .await;
        Ok(())
    }
}

#[async_trait]
impl StreamSink<Event> for ExecSink {
    async fn run(mut self: Box<Self>, mut input: BoxStream<'_, Event>) -> Result<(), ()> {
        match self.mode {
            Mode::Once => {
                let sem = self.child_semaphore.clone();
                let timeout =
                    std::time::Duration::from_millis(self.once_config.exec_timeout_milliseconds);
                while let Some(mut event) = input.next().await {
                    let finalizers = event.take_finalizers();
                    let command = self.command.join(" ").clone();
                    match tokio::time::timeout(
                        timeout.clone(),
                        sem.acquire()
                            .map_ok(|_| self.run_once(event))
                            .map_err(|e| {
                                emit!(ExecFailedError {
                                    command: command.as_str(),
                                    error: std::io::Error::new(
                                        std::io::ErrorKind::ResourceBusy,
                                        e.to_string()
                                    ),
                                });
                            })
                            .await?,
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            finalizers.update_status(EventStatus::Delivered);
                        }
                        Ok(Err(_)) => {
                            finalizers.update_status(EventStatus::Errored);
                        }
                        Err(e) => {
                            emit!(ExecFailedError {
                                command: command.as_str(),
                                error: std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    format!("Command timed out: {}", e),
                                ),
                            });
                            finalizers.update_status(EventStatus::Errored);
                        }
                    }
                }
                Ok(())
            }
            Mode::Streaming => self.run_streaming(input).await,
        }
    }
}
