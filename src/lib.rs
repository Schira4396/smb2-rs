mod negotiate;
mod sessionsetup1;
mod sessionsetup2;
mod error;

use std::io::Cursor;
use std::str::{FromStr};

use asn1_rs::nom::number::complete::{u32};
use asn1_rs::{Enumerated, FromDer, Oid, OctetString, OidParseError, ToDer};
use asn1_rs::nom::AsBytes;

use anyhow::{anyhow, Result};
use binrw::{BinRead, BinReaderExt, BinWrite};
use serde::{Deserialize, Serialize, };
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use ntlmclient;
use ntlmclient::{Flags, Message, TargetInfoType};
use rasn::{AsnType, Decode, Encode};
use crate::error::{SmbError, SmbResult};
use crate::negotiate::{NegotiateProtoResponse, NegotiateProtoRequset};

///This is a configuration item that tells smb2-rs the user name, password,
/// and other information you gave.
pub struct SmbOptions<'a> {
    pub Host : &'a str,
    pub Port : &'a str,
    pub User:        &'a str,
    pub Domain:      &'a str,
    pub Workstation: &'a str,
    pub Password:    &'a str,
    pub timeout: u16,
    sesionSetup1RespHeader: Header,
    sessionSetup1RespSecProvider: Vec<u8>,


}
// This structure is used to store the join results.
pub struct SmbInfo {
    pub isAuthenticated: bool,
    pub StatusCode: String
}










impl SmbOptions<'_> {
    pub fn new() -> Self {
        let s = SmbOptions {
            Host: "",
            Port: "",
            User: "",
            Domain: "",
            Workstation: "",
            Password: "",
            timeout: 0,
            sesionSetup1RespHeader: Header::new(),
            sessionSetup1RespSecProvider: vec![],
        };
        s
    }
}






///Core functions. All the logic is here.
impl SmbOptions<'_> {
    pub async fn Conn(&mut self) -> SmbResult<SmbInfo> {


        let target = format!("{}:{}", self.Host, self.Port);
        let t = tokio::time::Duration::from_secs(self.timeout as u64);

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
        //send negotiate req1
        NegotiateProtoRequset(&mut stream).await?;
        //parse nego proto response
        let negoprotoResp = NegotiateProtoResponse(&mut stream).await?;


        //send session setup req1
        self.SessionSetupRequset1(&mut stream, negoprotoResp).await?;


        //parse session setup resp1
        self.SessionSetUpResponse1(&mut stream).await?;

        //send session setup req2
        self.SessionSetupRequset2(&mut stream).await?;

        //--------------------------------

        //最后一个响应，只需要读取前68个字节，即4 + 64， 64字节即为header
        //parse result
        let mut buffer:Vec<u8> = vec![0;68];
        let _ = stream.read_exact(&mut buffer).await?;
        let mut cur = Cursor::new(buffer[4..].to_vec());

        let f:Header = cur.read_le()?;
        let login_result = u32::from_le_bytes(f.status.to_ne_bytes());

        stream.shutdown().await?;

        let r = SmbInfo{
            isAuthenticated: IsAuthenticated(login_result),
            StatusCode: format!("{:#010x}", login_result),
        };


        Ok(r)
    }
}









const DIALECT_SMB_2_1: i32 = 0x0210;

#[derive(BinRead, BinWrite, Debug)]
#[derive(Serialize, Deserialize, Copy, Clone)]
struct Header {
    protocol_id: [u8; 4],
    structure_size: u16,
    credit_charge: u16,
    status: u32,
    command: u16,
    credits: u16,
    flags: u32,
    next_command: u32,
    message_id: u64,
    reserved: u32,
    tree_id: u32,
    session_id: u64,
    signature: [u8; 16],
}

#[derive(BinRead, BinWrite, Debug)]
struct NegotiateReq  {
    header: Header,
    StructureSize:u16,
    DialectCount:u16,
    SecurityMode:u16,
    Reserved:u16,
    Capabilities: u32,
    ClientGuid:[u8; 16],
    ClientStartTime:u64,
    Dialects:[u16;1],
}



#[derive(Copy, Clone)]
enum  command {
    CommandNegotiate = 0,
    CommandSessionSetup = 1,
    CommandLogoff = 2,
    CommandTreeConnect = 3,
    CommandTreeDisconnect = 4,
    CommandCreate = 5,
    CommandClose = 6,
    CommandFlush = 7,
    CommandRead = 8,
    CommandWrite = 9,
    CommandLock = 10,
    CommandIOCtl = 11,
    CommandCancel = 12,
    CommandEcho = 13,
    CommandQueryDirectory = 14,
    CommandChangeNotify = 15,
    CommandQueryInfo = 16,
    CommandSetInfo = 17,
    CommandOplockBreak = 18
}

#[derive(Copy, Clone)]
enum SecMode {
    SecurityModeSigningEnabled = 1,
    SecurityModeSigningRequired = 2
}

#[derive(Copy, Clone)]
enum NegotiateFlags {
    FlgNegUnicode = 1 << 0 as u32,
    FlgNegOEM = 1 << 1,
    FlgNegRequestTarget = 1 << 2,
    FlgNegReserved10 = 1 << 3,
    FlgNegSign = 1 << 4,
    FlgNegSeal = 1 << 5,
    FlgNegDatagram = 1 << 6,
    FlgNegLmKey = 1 << 7,
    FlgNegReserved9 = 1 << 8,
    FlgNegNtLm = 1 << 9,
    FlgNegReserved8 = 1 << 10,
    FlgNegAnonymous = 1 << 11,
    FlgNegOEMDomainSupplied = 1 << 12,
    FlgNegOEMWorkstationSupplied = 1 << 13,
    FlgNegReserved7 = 1 << 14,
    FlgNegAlwaysSign = 1 << 15,
    FlgNegTargetTypeDomain = 1 << 16,
    FlgNegTargetTypeServer = 1 << 17,
    FlgNegReserved6 = 1 << 18,
    FlgNegExtendedSessionSecurity = 1 << 19,
    FlgNegIdentify = 1 << 20,
    FlgNegReserved5 = 1 << 21,
    FlgNegRequestNonNtSessionKey = 1 << 22,
    FlgNegTargetInfo = 1 << 23,
    FlgNegReserved4 = 1 << 24,
    FlgNegVersion = 1 << 25,
    FlgNegReserved3 = 1 << 26,
    FlgNegReserved2 = 1 << 27,
    FlgNegReserved1 = 1 << 28,
    FlgNeg128 = 1 << 29,
    FlgNegKeyExch = 1 << 30,
    FlgNeg56 = 1 << 31,
}
enum TagEnum {
    TypeEnum = 0x0a,
    TypeBitStr = 0x03,
    TypeOctStr = 0x04,
    TypeSeq = 0x30,
    TypeOid = 0x06,
}

enum NT_STATUS_Enum {
    STATUS_SUCCESS = 0,
    STATUS_LOGON_FAILURE = 3221225581

}





//wait.....
struct AuthMsg {
    header: [u8; 8],
    _type: [u8; 4],
    lmResp: Vec<u8>,
    ntlmResp: Vec<u8>,
    domain: String,
    user: String,
    workstation: String,
    flags: u32,
    lmRespLen: [u8; 2],
    lmRespMaxLen: [u8; 2],
    lmRespOffset: [u8; 4],




}






fn string_to_utf16_bytes(input: &str) -> Vec<u8> {
    let utf16_encoded: Vec<u16> = input.encode_utf16().collect();
    let mut utf16_bytes = Vec::new();
    for &code_unit in &utf16_encoded {
        utf16_bytes.push((code_unit & 0xFF) as u8);
        utf16_bytes.push((code_unit >> 8) as u8);
    }

    utf16_bytes
}


//

#[derive(Serialize, Deserialize, Debug)]
struct negotiate_Header  {
    signature:   [u8;8],
    message_type: u32
}
#[derive(Serialize, Deserialize, Debug)]
struct Negotiate  {
    negotiate_header: negotiate_Header,
    NegotiateFlags:          u32,
    DomainNameLen   :        u16,
    DomainNameMaxLen:        u16,
    DomainNameBufferOffset:  u32,
    WorkstationLen:          u16,
    WorkstationMaxLen:       u16,
    WorkstationBufferOffset: u32,
    DomainName:              Vec<u8>,
    Workstation :            Vec<u8>
}


#[derive(Serialize, Deserialize, Debug)]
struct NegTokenInit  {
    Oid: Box<[u8]>,
    Data: Negotiate_init_data
}


#[derive(Serialize, Deserialize, Debug)]
struct Negotiate_init_data {
    MechTypes: Vec<u8>,
    MechToken: Vec<u8>
}


#[derive(BinRead, BinWrite, Debug)]
#[derive(Serialize, Deserialize)]
struct SessionSetup1Req  {
    Header: Header,
    StructureSize    :    u16,
    Flags           :     u8,
    SecurityMode     :    u8,
    Capabilities    :     u32,
    Channel          :    u32,
    SecurityBufferOffset :  u16,
    SecurityBufferLength : u16,
    PreviousSessionID  :  u64,
}







impl Header {
    pub fn new() -> Header {
        let protocol_smb2: [u8; 4] = [0xFE, 0x53, 0x4D, 0x42];
        let arr: [u8; 16] = [0; 16];
        let qq = Header {
            protocol_id: protocol_smb2,
            structure_size: 64,
            credit_charge: 0,
            status: 0,
            command: 0,
            credits: 0,
            flags: 0,
            next_command: 0,
            message_id: 0,
            reserved: 0,
            tree_id: 0,
            session_id: 0,
            signature: arr,
        };
        qq
    }
}



///Calling this function gets the result of whether the connection was successful and the response code.
pub fn IsAuthenticated(code: u32) -> bool {
    match code {
        0 => {
            // println!("Status: Success")
            return true;
        },
        3221225581 => {
            println!("Status: Logon Failure")
        },
        _ => {
            println!("Status: Unknown")
        },
    }
    false
}

