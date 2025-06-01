use clap::Parser;
use simple_log::LogConfigBuilder;
use windows_service::service::ServiceType;
use windows_service::service::ServiceStatus;
use crate::service_control_handler::ServiceStatusHandle;
use tokio::runtime::Runtime;
use windows_service::service::ServiceControl;
use crate::service_control_handler::ServiceControlHandlerResult;
use windows_service::service_control_handler;
use windows_service::service_dispatcher;
use std::time::Duration;
use windows_service::service::ServiceExitCode;
use windows_service::service::ServiceControlAccept;
use windows_service::service::ServiceState;
use std::ffi::OsString;
use log::{error, info};
use secure_link_client::{SecureLink, SecureLinkError};
use winreg::RegKey;
use winreg::enums::*;
use winreg::types::ToRegValue;

#[macro_use]
extern crate windows_service;

static SECURE_LINK_SERVICE_NAME: &str = "Secure Link Service";
static REGISTRY_KEY_PATH: &str = "SOFTWARE\\SecureLinkService";
static REGISTRY_HOST_VALUE: &str = "SecureLink Server Host";
static REGISTRY_PORT_VALUE: &str = "SecureLink Server Port";
static REGISTRY_LOG_VALUE: &str = "Service Logfile";
static REGISTRY_AUTH_TOKEN_VALUE: &str = "Auth Token";

define_windows_service!(ffi_secure_link_service_main, secure_link_service_main);

static FAILED_TO_READ_ARGUMENTS_ERROR_CODE: u32 = 1;
static FAILED_TO_GET_AUTH_TOKEN_FROM_CREDENTIAL_MANAGER: u32 = 2;
static FAILED_TO_CREATE_TOKIO_RUNTIME: u32 = 3;
static FAILED_TO_CONNECT_TO_SECURE_LINK_SERVER: u32 = 4;
static FAILED_UNAUTHORIZED: u32 = 5;
static SECURE_LINK_STOPPED_WITH_ERROR: u32 = 6;
static FAILED_TO_SETUP_LOGGER: u32 = 7;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    service_dispatcher::start(SECURE_LINK_SERVICE_NAME, ffi_secure_link_service_main)?;

    Ok(())
}

fn get_service_reg_key() -> Result<RegKey, Box<dyn std::error::Error>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.create_subkey(REGISTRY_KEY_PATH)?.0;

    Ok(key)
}

fn store_entry_in_registry<T: ToRegValue>(key: &str, entry: &T) -> Result<(), Box<dyn std::error::Error>> {
    let reg_key = get_service_reg_key()?;
    reg_key.set_value(key, entry)?;
    Ok(())
}
fn load_entry_from_registry<T: winreg::types::FromRegValue>(key: &str) -> Result<T, Box<dyn std::error::Error>> {
    let reg_key = get_service_reg_key()?;
    Ok(reg_key.get_value::<T, _>(key)?)
}


#[derive(Parser, Debug)]
struct Args {
    #[clap(long)]
    set_host: Option<String>,
    #[clap(long)]
    set_port: Option<u16>,
    #[clap(long)]
    set_log_file_path: Option<String>
}
fn load_args(arguments: Vec<OsString>) -> Result<(String, u16, String), Box<dyn std::error::Error>> {
    
    let args = Args::try_parse_from(
        arguments
            .iter()
            .filter(|os| os.to_str().is_some())
            .map(|os| os.to_str().unwrap())
    )?;
    

    let host =
        if let Some(host) = args.set_host {

            store_entry_in_registry(REGISTRY_HOST_VALUE, &host)?;
            host
        }
        else
        {
            load_entry_from_registry(REGISTRY_HOST_VALUE)?
        };

    let port =
        if let Some(port) = args.set_port {
            store_entry_in_registry(REGISTRY_PORT_VALUE, &(port as u32))?;
            port
        }
        else
        {
            load_entry_from_registry::<u32>(REGISTRY_PORT_VALUE)? as u16
        };

    let log_file_path =
        if let Some(log_file_path) = args.set_log_file_path {

            store_entry_in_registry(REGISTRY_LOG_VALUE, &log_file_path)?;

            log_file_path
        }
        else
        {
            load_entry_from_registry(REGISTRY_LOG_VALUE)?
        };

   Ok((host, port, log_file_path))

}

fn setup_file_logger(log_file_path: &str) -> Result<(), Box<dyn std::error::Error>> {

    let config = LogConfigBuilder::builder()
        .path(log_file_path)
        .size(1 * 100)
        .roll_count(10)
        .level("info")?
        .output_file()
        .output_console()
        .build();

    simple_log::new(config)?;

    Ok(())
}

fn secure_link_service_main(arguments: Vec<OsString>) {

    let (shutdown_signal_sender, mut shutdown_signal_receiver) = tokio::sync::mpsc::unbounded_channel();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                // Handle stop event and return control back to the system.
                shutdown_signal_sender.send(()).unwrap();
                ServiceControlHandlerResult::NoError
            }
            // All services must accept Interrogate even if it's a no-op.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let acuiring_service_status_handle_result = service_control_handler::register(SECURE_LINK_SERVICE_NAME, event_handler);

    let status_handle =
        match acuiring_service_status_handle_result {
            Ok(status_handle) => {
                // Report service is starting
                report_service_status(
                    &status_handle,
                    ServiceState::StartPending,
                    ServiceControlAccept::STOP,
                    ServiceExitCode::Win32(0),
                    Duration::from_secs(25),
                );

                status_handle
            },

            Err(err) => {
                error!("Failed to accure service status handler, {}", err);
                return;
            }
        };

    let (secure_link_server_host, secure_link_server_port, log_file_path) =
        match load_args(arguments) {
            Ok(args) => args,
            Err(err) => {

                error!("Failed to load arguments, {}", err);

                report_service_status(
                    &status_handle,
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::ServiceSpecific(FAILED_TO_READ_ARGUMENTS_ERROR_CODE),
                    Duration::from_secs(0),
                );

                return;
            }
        };

    match setup_file_logger(&log_file_path) {

        Ok(()) => {}

        Err(err) => {

            error!("Failed to setup logger: {}", err);

            report_service_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(FAILED_TO_SETUP_LOGGER),
                Duration::from_secs(0),
            );

        }
        
    }


    let auth_token = match load_entry_from_registry::<String>(REGISTRY_AUTH_TOKEN_VALUE) {
        Ok(token) => token,
        Err(e) => {

            error!("Failed to load auth token: {}", e);

            report_service_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(FAILED_TO_GET_AUTH_TOKEN_FROM_CREDENTIAL_MANAGER),
                Duration::from_secs(0),
            );

            return;
        }
    };

    info!("got {auth_token} auth token in cred manager, key {REGISTRY_AUTH_TOKEN_VALUE}");

    let rt = match Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {

            error!("Failed to create Tokio runtime: {}", e);

            report_service_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(FAILED_TO_CREATE_TOKIO_RUNTIME),
                Duration::from_secs(0),
            );
            return;
        }
    };

    rt.block_on(async {
        let secure_link_connection_future =
            SecureLink::connect_to_global_channel(
                &secure_link_server_host,
                secure_link_server_port,
                &auth_token
            );

        let secure_link_connection_result = tokio::select! {
            res = secure_link_connection_future => {
                res
            }

            _ = shutdown_signal_receiver.recv() => {
                report_service_status(
                   &status_handle,
                   ServiceState::Stopped,
                   ServiceControlAccept::empty(),
                   ServiceExitCode::Win32(0),
                   Duration::from_secs(0),
                );

                return
            }
        };

        match secure_link_connection_result {
            Ok(secure_link) => {
                report_service_status(
                    &status_handle,
                    ServiceState::Running,
                    ServiceControlAccept::STOP,
                    ServiceExitCode::Win32(0),
                    Duration::from_secs(0),
                );

                let secure_link_message_loop_future = secure_link.run_message_loop();

                let result = tokio::select! {
                    res = secure_link_message_loop_future => {
                        res
                    }

                    _ = shutdown_signal_receiver.recv() => {
                        report_service_status(
                           &status_handle,
                           ServiceState::Stopped,
                           ServiceControlAccept::empty(),
                           ServiceExitCode::Win32(0),
                           Duration::from_secs(0),
                        );

                        return
                    }
                };

                match result {
                    Ok(()) => {
                        report_service_status(
                            &status_handle,
                            ServiceState::Stopped,
                            ServiceControlAccept::empty(),
                            ServiceExitCode::Win32(0),
                            Duration::from_secs(0),
                        );
                    }

                    Err(err) => {

                        error!("{}", err);

                        report_service_status(
                            &status_handle,
                            ServiceState::Stopped,
                            ServiceControlAccept::empty(),
                            ServiceExitCode::ServiceSpecific(SECURE_LINK_STOPPED_WITH_ERROR),
                            Duration::from_secs(0),
                        );

                    }
                }
            }

            Err(err) => {

                match err {
                    SecureLinkError::UnauthorizedError => {

                        report_service_status(
                            &status_handle,
                            ServiceState::Stopped,
                            ServiceControlAccept::empty(),
                            ServiceExitCode::ServiceSpecific(FAILED_UNAUTHORIZED),
                            Duration::from_secs(0),
                        );

                    }

                    err => {


                        error!("Failed to connect to secure link server: {}", err);

                        report_service_status(
                            &status_handle,
                            ServiceState::Stopped,
                            ServiceControlAccept::empty(),
                            ServiceExitCode::ServiceSpecific(FAILED_TO_CONNECT_TO_SECURE_LINK_SERVER),
                            Duration::from_secs(0),
                        );

                    }
                }

            }
        }
    });
}

fn report_service_status(
    status_handle: &ServiceStatusHandle,
    state: ServiceState,
    controls: ServiceControlAccept,
    exit_code: ServiceExitCode,
    wait_hint: Duration,
) {
    let status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: controls,
        exit_code,
        checkpoint: 0,
        wait_hint,
        process_id: None,
    };

    if let Err(e) = status_handle.set_service_status(status) {
        error!("Failed to set service status: {}", e);
    }
}
