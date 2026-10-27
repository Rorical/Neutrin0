//! Local node controls use a private socket independently of the public RPC client.

use neutrin0_rpc::management::ManagementRequest;

use super::{Arguments, Error};

pub(super) fn request(group: &str, operation: &str) -> Option<ManagementRequest> {
    match (group, operation) {
        ("node", "control-status") => Some(ManagementRequest::Status),
        ("node", "shutdown") => Some(ManagementRequest::Shutdown),
        ("validator", "pause-signing") => Some(ManagementRequest::PauseSigning),
        ("validator", "resume-signing") => Some(ManagementRequest::ResumeSigning),
        ("validator", "pause-production") => Some(ManagementRequest::PauseProduction),
        ("validator", "resume-production") => Some(ManagementRequest::ResumeProduction),
        // Its path and anchor come from the options (`with_options`).
        ("node", "export-snapshot") => Some(ManagementRequest::ExportSnapshot {
            path: String::new(),
            anchor_chunks: None,
        }),
        _ => None,
    }
}

/// Options a management command takes beyond the socket.
pub(super) const fn flags(request: &ManagementRequest) -> &'static [&'static str] {
    match request {
        ManagementRequest::ExportSnapshot { .. } => &["out", "anchor-chunks"],
        _ => &[],
    }
}

/// `request` completed from its options.
fn with_options(
    request: ManagementRequest,
    options: &Arguments,
) -> Result<ManagementRequest, Error> {
    let ManagementRequest::ExportSnapshot { .. } = request else {
        return Ok(request);
    };
    let path = std::path::absolute(
        options
            .get("out")
            .ok_or_else(|| Error::Usage("missing --out <file>".into()))?,
    )
    .map_err(|error| Error::Usage(error.to_string()))?;
    let anchor_chunks = options
        .get("anchor-chunks")
        .map(|value| {
            value
                .parse()
                .map_err(|_| Error::Usage("--anchor-chunks must be a chunk count".into()))
        })
        .transpose()?;
    Ok(ManagementRequest::ExportSnapshot {
        path: path.display().to_string(),
        anchor_chunks,
    })
}

pub(super) async fn run(request: ManagementRequest, options: &Arguments) -> Result<u8, Error> {
    let request = with_options(request, options)?;
    if options.get("rpc").is_some() {
        return Err(Error::Usage(
            "local controls use --management-socket, not --rpc".into(),
        ));
    }
    #[cfg(unix)]
    {
        use neutrin0_rpc::management::{ManagementResponse, management_call};
        let path = options
            .get("management-socket")
            .map(str::to_owned)
            .or_else(|| std::env::var("NEUTRIN0_MANAGEMENT_SOCKET").ok())
            .ok_or_else(|| {
                Error::Usage("missing --management-socket (or NEUTRIN0_MANAGEMENT_SOCKET)".into())
            })?;
        // An export writes the whole state, so it may take long.
        let default_timeout = match request {
            ManagementRequest::ExportSnapshot { .. } => 24 * 3600,
            _ => 10,
        };
        let response = management_call(
            std::path::Path::new(&path),
            request,
            options.duration("timeout-secs", default_timeout)?,
        )
        .await
        .map_err(|error| Error::Local(error.to_string()))?;
        match response {
            ManagementResponse::Ok { status } => {
                options.output(&super::to_value(status)?, false)?;
                Ok(0)
            }
            ManagementResponse::Exported { snapshot } => {
                options.output(&super::to_value(snapshot)?, false)?;
                Ok(0)
            }
            ManagementResponse::Error { message } => Err(Error::Local(message)),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Err(Error::Local(
            "local management requires Unix sockets".into(),
        ))
    }
}
