use thiserror::Error;
use std::io;
use tokio::time::error::Elapsed;

/// Error of Rdp protocol
#[derive(Debug, Error)]
pub enum SmbError {
    /// can not connect to server
    #[error(transparent)]
    SmbConnectionTimeOut(#[from] Elapsed),

    /// can not connect to server
    #[error(transparent)]
    SmbParseError(#[from] binrw::Error),
    
    
    #[error(transparent)]
    SmbConnectionError(#[from] io::Error),
    

    #[error("Parse address error：{0}")]
    SmbDomainError(#[from] std::net::AddrParseError),


    /// auth failed or err
    #[error("auth error：{reason}")]
    SmbAuthentication {
        reason: String,
    },

    /// RDP protocol parse error
    #[error("protocol error：{0}")]
    SmbProtocolError(String),

    /// session closed
    #[error("session closed")]
    SmbDisconnected,

    #[error(transparent)]
    SmbOther(#[from] anyhow::Error),
}




pub type SmbResult<T> = Result<T, SmbError>;
