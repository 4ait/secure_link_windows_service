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
use secure_link_client::SecureLink;
use windows_credential_manager_rs::CredentialManager;
use winreg::RegKey;
use winreg::enums::*;

#[macro_use]
extern crate windows_service;

static SECURE_LINK_SERVICE_NAME: &str = "Secure Link Service";
static SECURE_LINK_SERVICE_AUTH_TOKEN_KEY: &str = "secure-link-service:auth-token-key";
static REGISTRY_KEY_PATH: &str = "SOFTWARE\\SecureLinkService";
static REGISTRY_HOST_VALUE: &str = "SecureLink Server Host";
static REGISTRY_PORT_VALUE: &str = "SecureLink Server Port";

define_windows_service!(ffi_secure_link_service_main, secure_link_service_main);

static FAILED_TO_READ_ARGUMENTS_ERROR_CODE: u32 = 1;
static FAILED_TO_GET_AUTH_TOKEN_FROM_CREDENTIAL_MANAGER: u32 = 2;
static FAILED_TO_CREATE_TOKIO_RUNTIME: u32 = 3;
static FAILED_TO_CONNECT_TO_SECURE_LINK_SERVER: u32 = 4;
static SECURE_LINK_STOPPED_WITH_ERROR: u32 = 5;
static FAILED_TO_ACCESS_REGISTRY: u32 = 6;

fn main() -> Result<(), Box<dyn std::error::Error>> {
   
    service_dispatcher::start(SECURE_LINK_SERVICE_NAME, ffi_secure_link_service_main)?;

    Ok(())
}

fn store_host_port_in_registry(host: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.create_subkey(REGISTRY_KEY_PATH)?.0;

    key.set_value(REGISTRY_HOST_VALUE, &host)?;
    key.set_value(REGISTRY_PORT_VALUE, &(port as u32))?;

    Ok(())
}

fn load_host_port_from_registry() -> Result<(String, u16), Box<dyn std::error::Error>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey(REGISTRY_KEY_PATH)?;

    let host: String = key.get_value(REGISTRY_HOST_VALUE)?;
    let port: u32 = key.get_value(REGISTRY_PORT_VALUE)?;

    if port > u16::MAX as u32 {
        return Err("Port value in registry is out of range".into());
    }

    Ok((host, port as u16))
}

fn load_args(arguments: Vec<OsString>) -> Result<(String, u16), Box<dyn std::error::Error>> {
    
    let first_arg =
        arguments.get(0)
            .map(|os| os.to_str().unwrap_or(""));

    let start_index =
        if first_arg == Some(SECURE_LINK_SERVICE_NAME) {
            1
        } else {
            0
        };

    // Check if we have host and port arguments
    if let (Some(host_arg), Some(port_arg)) = (arguments.get(start_index), arguments.get(start_index + 1)) {
        // Arguments provided - parse and store them in registry
        let host = host_arg.to_str().ok_or("failed to parse host argument")?.to_string();
        let port = port_arg.to_str().ok_or("failed to parse port argument")?.parse::<u16>()?;

        // Store in registry for future use
        store_host_port_in_registry(&host, port)?;

        Ok((host, port))
    } else {
        // No arguments provided - load from registry
        load_host_port_from_registry()
    }
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
                    ServiceControlAccept::empty(),
                    ServiceExitCode::Win32(0),
                    Duration::from_secs(30),
                );

                status_handle
            },

            Err(err) => {
                eprintln!("Failed to accure service status handler, {}", err);
                return;
            }
        };

    let (secure_link_server_host, secure_link_server_port) =
        match load_args(arguments) {
            Ok(args) => args,
            Err(err) => {
                eprintln!("{}", err);

                let error_code = if err.to_string().contains("registry") || err.to_string().contains("Registry") {
                    FAILED_TO_ACCESS_REGISTRY
                } else {
                    FAILED_TO_READ_ARGUMENTS_ERROR_CODE
                };

                report_service_status(
                    &status_handle,
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::ServiceSpecific(error_code),
                    Duration::from_secs(0),
                );

                return;
            }
        };

    let auth_token = match CredentialManager::get_token(SECURE_LINK_SERVICE_AUTH_TOKEN_KEY) {
        Ok(token) => token,
        Err(e) => {
            eprintln!("Failed to load auth token: {}", e);

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

    let rt = match Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("Failed to create Tokio runtime: {}", e);
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
                        eprintln!("{}", err);

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
                report_service_status(
                    &status_handle,
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::ServiceSpecific(FAILED_TO_CONNECT_TO_SECURE_LINK_SERVER),
                    Duration::from_secs(0),
                );

                eprintln!("Failed to connect to secure link server: {}", err);
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
        eprintln!("Failed to set service status: {}", e);
    }
}