use crate::{
    codecs::{EncodingConfigWithFraming, SinkType},
    internal_events::ExecFailedError,
    sinks::prelude::*,
};
use bytes::BytesMut;
use serde_with::serde_as;
use std::{collections::HashMap, path::PathBuf, sync::Arc}; //, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command, sync::Mutex};
use tokio_util::codec::Encoder as _;
use vector_lib::codecs::{
    encoding::{Framer, FramingConfig},
    TextSerializerConfig,
};

use std::process::Stdio;
//use vector_lib::internal_event::{EventsSent, Output, Registered};

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

const fn default_once_mode() -> OnceMode {
    OnceMode::Argument
}
const fn default_exec_timeout_secs() -> u64 {
    60
}
const fn default_respawn_on_exit() -> bool {
    false
}
const fn default_respawn_interval_secs() -> u64 {
    5
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
    #[serde(default = "default_once_mode")]
    #[configurable(metadata(docs::human_name = "Mode"))]
    mode: OnceMode,
    /// The maximum amount of time, in seconds, to wait for the command to finish.
    ///
    /// If the command takes longer than `exec_timeout_secs` to run, it is killed.
    #[serde(default = "default_exec_timeout_secs")]
    #[configurable(metadata(docs::human_name = "Timeout"))]
    exec_timeout_secs: u64,
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
            once: Some(OnceConfig {
                mode: OnceMode::Argument,
                exec_timeout_secs: default_exec_timeout_secs(),
            }),
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
    once_config: Option<OnceConfig>,
    //streaming_config: Option<StreamingConfig>,
    //events_sent: Registered<EventsSent>,
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
            once_config: config.once.clone(),
            //streaming_config: config.streaming.clone(),
            //events_sent: register!(EventsSent::from(Output(None))),
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
        let config = self.once_config.as_ref().expect("once config must be set");

        match config.mode {
            OnceMode::Argument => {
                let mut encoded = BytesMut::new();
                self.transformer.transform(&mut event);
                self.encoder.encode(event.clone(), &mut encoded).unwrap();

                let mut cmd = self.build_command();
                cmd.arg(String::from_utf8_lossy(&encoded).to_string());
                cmd.stdout(Stdio::null());
                cmd.stderr(Stdio::null());

                let status = cmd.status().await.map_err(|e| {
                    emit!(ExecFailedError {
                        command: self.command.join(" ").as_str(),
                        error: e,
                    });
                })?;

                if status.success() {
                    let finalizers = event.take_finalizers();
                    finalizers.update_status(EventStatus::Delivered);
                    Ok(())
                } else {
                    event.metadata().update_status(EventStatus::Errored);
                    Err(())
                }
            }
            OnceMode::Pipe => {
                let mut cmd = self.build_command();
                cmd.stdin(Stdio::piped());
                cmd.stdout(Stdio::null());
                cmd.stderr(Stdio::null());

                let mut child = cmd.spawn().map_err(|e| {
                    emit!(ExecFailedError {
                        command: self.command.join(" ").as_str(),
                        error: e,
                    });
                })?;

                let stdin = child.stdin.as_mut().expect("Failed to get stdin");

                let mut encoded = BytesMut::new();
                self.transformer.transform(&mut event);
                self.encoder.encode(event.clone(), &mut encoded).unwrap();

                tokio::io::AsyncWriteExt::write_all(stdin, &encoded)
                    .await
                    .map_err(|e| {
                        emit!(ExecFailedError {
                            command: self.command.join(" ").as_str(),
                            error: e,
                        });
                    })?;

                //drop(stdin); // Close stdin to signal EOF

                let status = child.wait().await.map_err(|e| {
                    emit!(ExecFailedError {
                        command: self.command.join(" ").as_str(),
                        error: e,
                    });
                })?;

                if status.success() {
                    let finalizers = event.take_finalizers();
                    finalizers.update_status(EventStatus::Delivered);
                    Ok(())
                } else {
                    event.metadata().update_status(EventStatus::Errored);
                    Err(())
                }
            }
        }
    }

    async fn run_streaming(&mut self, input: BoxStream<'_, Event>) -> Result<(), ()> {
        let mut cmd = self.build_command();
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());

        let child = cmd
            .spawn()
            .map_err(|e| {
                emit!(ExecFailedError {
                    command: self.command.join(" ").as_str(),
                    error: e,
                });
            })
            .expect("Failed to spawn command");

        let stdin = Arc::new(Mutex::new(child.stdin.expect("Failed to get stdin")));

        let transformer = self.transformer.clone();

        let command = self.command.join(" ").to_string();

        input
            .for_each(|event| {
                let command = command.clone();
                let mut encoder = self.encoder.clone();
                let transformer = transformer.clone();
                let stdin = stdin.clone();
                async move {
                    let mut event = event;
                    let mut stdin = stdin.lock().await;

                    transformer.transform(&mut event);
                    let mut encoded = BytesMut::new();
                    encoder.encode(event.clone(), &mut encoded).unwrap();

                    if stdin.write_all(&encoded).await.is_err() {
                        emit!(ExecFailedError {
                            command: command.as_str(),
                            error: std::io::Error::new(std::io::ErrorKind::Other, "write error"),
                        });
                        event.metadata().update_status(EventStatus::Errored);
                        return;
                    }

                    let finalizers = event.take_finalizers();
                    finalizers.update_status(EventStatus::Delivered);
                }
            })
            .await;

        drop(stdin);

        Ok(())
    }
}

#[async_trait]
impl StreamSink<Event> for ExecSink {
    async fn run(mut self: Box<Self>, mut input: BoxStream<'_, Event>) -> Result<(), ()> {
        match self.mode {
            Mode::Once => {
                while let Some(event) = input.next().await {
                    self.run_once(event).await?;
                }
                Ok(())
            }
            Mode::Streaming => self.run_streaming(input).await,
        }
    }
}
