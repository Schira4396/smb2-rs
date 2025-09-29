use std::io::Cursor;
use anyhow::anyhow;
use binrw::{BinRead, BinReaderExt, BinWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::error::{SmbError, SmbResult};
use crate::smb1::{smb1Header, NegoReqBody, NegoRequest, SmbHeaderFlags, SmbHeaderFlags2, SmbOptions1};
use crate::smb2::{NegotiateProtoResponse, SmbInfo, SmbOptions2};

pub mod error;
pub mod smb1;

pub mod smb2;

#[derive(Default)]
pub struct SmbOption {
    pub Host : String,
    pub Port : String,
    pub User:        String,
    pub Domain:      String,
    pub Workstation: String,
    pub Password:    String,
    pub timeout: u16,
    pub ntlmhash: Option<String>,
}

impl SmbOption {
    pub fn new() -> Result<SmbOption, SmbError> {
        let mut s = SmbOption::default();
        s.ntlmhash = None;
        Ok(s)
    }
    pub fn setHash(&mut self, hash: &str) {
        self.ntlmhash = Some(hash.to_string());
    }
}

impl SmbOption {
    pub async fn Connect(&mut self) -> SmbResult<SmbInfo> {
        let target = format!("{}:{}", self.Host, self.Port);
        let mut t = tokio::time::Duration::from_secs(self.timeout as u64);
        //connect to server
        let mut stream = match tokio::time::timeout(t, TcpStream::connect(target.clone())).await {
            Ok(r) => {
                match r {
                    Ok(r) => r,
                    Err(e) => return Err(SmbError::from(anyhow!(e))),
                }
            },
            Err(e) => return Err(SmbError::from(anyhow!(e))),

        };










        let negoReq = self.GetNegoMessage()?;
        let len = negoReq.len();
        let mut r1 = (len as u32).to_be_bytes().to_vec();
        r1.extend_from_slice(&negoReq);

        //send nego req
        stream.write_all(&r1).await?;


        let negoprotoResp = NegotiateProtoResponse(&mut stream).await?;
        let protocolHeader = negoprotoResp.protocol_id;


        if protocolHeader[0] == 0xFF {
            let mut op1 = SmbOptions1::New();
            op1.Host = self.Host.as_str();
            op1.Port = self.Port.as_str();
            op1.timeout = self.timeout;
            op1.User = self.User.as_str();
            op1.Domain = self.Domain.as_str();
            op1.Workstation = self.Workstation.as_str();
            op1.Password = self.Password.as_str();
            match &self.ntlmhash {
                Some(hash) => {
                    let h = hex::decode(hash).map_err(|e| SmbError::from(anyhow!(e)))?;
                    if h.len() != 16 {
                        return Err(SmbError::from(anyhow!("ntlmhash length mismatch")));
                    }
                    op1.hash = h.try_into().map_err(|e| SmbError::from(anyhow!("ntlmhash length mismatch")))?;
                }
                None => {}
            }
            let res = op1.Connect(&mut stream).await;
            match res {
                Ok(r) => {
                    // if r.isAuthenticated {
                    //     println!("Authenticated");
                    //     println!("status_code: {}", r.StatusCode);
                    // }else {
                    //     println!("Not Authenticated");
                    //     println!("status_code: {}", r.StatusCode);
                    // }
                    Ok(r)
                }
                Err(e) => {
                    // println!("Error: {:?}", e);
                    Err(SmbError::from(anyhow!(e)))
                }

            }
        }else {
            let mut options = SmbOptions2::new();
            options.Workstation = self.Workstation.as_str();
            options.Domain = self.Domain.as_str();
            options.Host = self.Host.as_str();
            options.Port = self.Port.as_str();
            options.timeout = self.timeout;
            options.User = self.User.as_str();
            options.Password = self.Password.as_str();
            match &self.ntlmhash {
                Some(hash) => {
                    let h = hex::decode(hash).map_err(|e| SmbError::from(anyhow!(e)))?;
                    if h.len() != 16 {
                        return Err(SmbError::from(anyhow!("ntlmhash length mismatch")));
                    }
                    options.hash = h.try_into().map_err(|e| SmbError::from(anyhow!("ntlmhash length mismatch")))?;
                }
                None => {}
            }
            let result = options.Conn(&mut stream, negoprotoResp).await;
            match result {
                Ok(r) => {
                    // if r.isAuthenticated {
                    //     println!("Authenticated");
                    //     println!("status_code: {}", r.StatusCode);
                    // }else {
                    //     println!("Not Authenticated");
                    //     println!("status_code: {}", r.StatusCode);
                    // }
                    Ok(r)
                }
                Err(e) => {
                    // println!("Error: {:?}", e)
                    Err(SmbError::from(anyhow!(e)))
                }

            }
        }

    }

    pub fn GetNegoMessage(&mut self) -> anyhow::Result<Vec<u8>> {
        let f1 =
            SmbHeaderFlags::CANONICALIZED_PATHS | SmbHeaderFlags::CASELESS_PATHNAMES;
        let f2 = SmbHeaderFlags2::FLAGS2_LONG_NAMES
            | SmbHeaderFlags2::FLAGS2_EXTENDED_SECURITY
            | SmbHeaderFlags2::FLAGS2_NT_STATUS;
        let mut h = smb1Header {
            serverComponent: [0xff, 0x53, 0x4d, 0x42],
            command: 0x72,
            status: [0, 0, 0, 0],
            flags: f1.bits(),
            flags2: f2.bits().to_le_bytes(),
            processidHigh: [0u8; 2],
            signature: [0u8; 8],
            reserved: [0u8; 2],
            treeId: [0xff; 2],
            processId: [0xff, 0xfe],
            userId: [0u8; 2],
            mutiplex: [0u8; 2],
        };
        h.processId = [0u8; 2];
        h.treeId = 65535u16.to_le_bytes();

        let n = NegoReqBody {
            wordCount: 0,
            ByteCount: 23u16.to_le_bytes(),
            data: smb1::Dialects_smbv1,
        };

        let r = NegoRequest {
            header: h,
            nego: n,
        };
        let mut data = Cursor::new(Vec::<u8>::new());
        r.write_le(&mut data)?;

        Ok(data.into_inner())
    }
}


struct negoResp {
    header: smb1Header,

}

