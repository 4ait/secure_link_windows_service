

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

#[macro_use]
extern crate windows_service;

static SECURE_LINK_SERVICE_NAME: &str = "Secure Link Service";
static SECURE_LINK_SERVICE_AUTH_TOKEN_KEY: &str = "secure-link-service:auth-token-key";

define_windows_service!(ffi_secure_link_service_main, secure_link_service_main);

fn main() -> Result<(), Box<dyn std::error::Error>> {


    service_dispatcher::start(SECURE_LINK_SERVICE_NAME, ffi_secure_link_service_main)?;

    Ok(())
}


fn secure_link_service_main(_arguments: Vec<OsString>) {


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


    let secure_link_server_host = "192.168.12.16";
    let secure_link_server_port: u16 = 6001;

    let auth_token = match CredentialManager::get_token(SECURE_LINK_SERVICE_AUTH_TOKEN_KEY) {
        Ok(token) => token,
        Err(e) => {
            eprintln!("Failed to load auth token: {}", e);

            report_service_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(2),
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
                ServiceExitCode::ServiceSpecific(1),
                Duration::from_secs(0),
            );
            return;
        }
    };


    rt.block_on(async {

        let secure_link_connection_future =
            SecureLink::connect_to_global_channel(
                secure_link_server_host,
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
                            ServiceExitCode::ServiceSpecific(4),
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
                    ServiceExitCode::ServiceSpecific(3),
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
