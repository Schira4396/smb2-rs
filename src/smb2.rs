use std::io::Cursor;
use std::str::{FromStr};



use anyhow::{anyhow, Result};
use binrw::{BinRead, BinReaderExt, BinWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use ntlmclient;
use ntlmclient::{Flags, Message, TargetInfoType};
use rasn::{der, AsnType, Decode, Encode, Encoder, Decoder};
use rasn::types::{ObjectIdentifier, OctetString, Oid};
use crate::error::{IsAuthenticated, SmbError, SmbResult};

///This is a configuration item that tells smb2-rs the user name, password,
/// and other information you gave.
pub(crate) struct SmbOptions2<'a> {
    pub Host : &'a str,
    pub Port : &'a str,
    pub User:        &'a str,
    pub Domain:      &'a str,
    pub Workstation: &'a str,
    pub Password:    &'a str,
    pub timeout: u16,
    sesionSetup1RespHeader: Header,
    sessionSetup1RespSecProvider: Vec<u8>,
    pub(crate) hash: [u8; 16],


}
// This structure is used to store the join results.
pub struct SmbInfo {
    pub isAuthenticated: bool,
    pub StatusCode: String
}










impl SmbOptions2<'_> {
    pub fn new() -> Self {
        let s = SmbOptions2 {
            Host: "",
            Port: "",
            User: "",
            Domain: "",
            Workstation: "",
            Password: "",
            timeout: 0,
            sesionSetup1RespHeader: Header::new(),
            sessionSetup1RespSecProvider: vec![],
            hash: [0u8;16],
        };
        s
    }
}






///Core functions. All the logic is here.
impl SmbOptions2<'_> {
    pub async fn Conn(&mut self, mut stream: &mut TcpStream, negoprotoResp: Header) -> SmbResult<SmbInfo> {



        // //send negotiate req1
        // NegotiateProtoRequset(&mut stream).await?;
        // //parse nego proto response
        // let negoprotoResp = NegotiateProtoResponse(&mut stream).await?;


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

pub(crate) struct Header {
    pub(crate) protocol_id: [u8; 4],
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


struct negotiate_Header  {
    signature:   [u8;8],
    message_type: u32
}

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



struct NegTokenInit  {
    Oid: Box<[u8]>,
    Data: Negotiate_init_data
}


struct Negotiate_init_data {
    MechTypes: Vec<u8>,
    MechToken: Vec<u8>
}


#[derive(BinRead, BinWrite, Debug)]
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




pub async fn NegotiateProtoRequset(mut stream: &mut TcpStream) -> Result<()> {
    let mut newheader = Header::new();
    newheader.command = command::CommandNegotiate as u16;
    newheader.credit_charge = 1u16;
    newheader.message_id = 0u64;
    let dialects = [DIALECT_SMB_2_1 as u16];

    let req =  NegotiateReq {
        header: newheader,
        StructureSize: 36,
        DialectCount: dialects.len() as u16,
        SecurityMode: SecMode::SecurityModeSigningEnabled as u16,
        Reserved: 0,
        Capabilities: 0,
        ClientGuid: [0;16],
        ClientStartTime: 0,
        Dialects: dialects,
    };


    let mut serialized_data = Cursor::new(Vec::<u8>::new());
    req.write_le(&mut serialized_data)?;
    let mut serialized_data = serialized_data.into_inner();
    let mut metadata = Cursor::new(Vec::<u8>::new());
    (serialized_data.len() as u32).write_be(&mut metadata)?;
    let mut metadata = metadata.into_inner();

    metadata.extend_from_slice(&serialized_data);
    stream.write_all(&metadata).await?;
    stream.flush().await?;

    Ok(())

}



pub async fn NegotiateProtoResponse(mut stream: &mut TcpStream) -> Result<Header> {

    let mut res_header:[u8;4] = [0;4];
    let res = stream.read_exact(&mut res_header).await?;
    let body_size = u32::from_be_bytes(res_header) as usize;
    let mut res_data:Vec<u8> = vec![0; body_size ];
    let _ = stream.read_exact(&mut res_data).await?;
    let ProtoColID = &res_data[0..4];

    let mut cur = Cursor::new(&res_data[0..64]);
    let des_data:Header = cur.read_be()?;





    let respLen = res_data.len() - 64;
    ///////////////////////
    //   !!!!需要完善！！！///
    ///////////////////////
    // parse_security_blob(&res_data[64..]);
    // println!("start,,,,");
    // let mut ttt:[u8;100] = [0;100];
    // let x = stream.read_exact(&mut ttt).await?;
    Ok(des_data)
}

const OID1: &[u32] = &[1, 3, 6, 1, 5, 5, 2];
const OID2: &[u32] = &[1, 3, 6, 1, 4, 1, 311, 2, 2, 10];

impl SmbOptions2<'_> {
    pub async fn SessionSetupRequset1(&mut self, mut stream: &mut TcpStream, n: Header) -> anyhow::Result<()> {


        let mut header = Header::new();
        header.credit_charge = 1;
        header.command = command::CommandSessionSetup as u16;
        header.message_id = n.session_id + 1;
        header.session_id = n.session_id;

        let f
            = Flags::NEGOTIATE_56BIT
            | Flags::NEGOTIATE_128BIT
            | Flags::NEGOTIATE_TARGET_INFO
            | Flags::NEGOTIATE_NTLM2_KEY
            | Flags::NEGOTIATE_DOMAIN_SUPPLIED
            | Flags::NEGOTIATE_NTLM
            | Flags::REQUEST_TARGET
            | Flags::NEGOTIATE_UNICODE
            ;






        let mut req = SessionSetup1Req {
            Header: header,
            StructureSize: 25,
            Flags: 0x00,
            SecurityMode: 1,
            Capabilities: f.bits(),
            Channel: 0,
            SecurityBufferOffset: 88,
            SecurityBufferLength: 0,
            PreviousSessionID: 0,

        };


        let (a, b) = self.GeneraeSecBlob()?;
        req.SecurityBufferLength = b;
        let mut cur = Cursor::new(Vec::new());
        req.write_le(&mut cur)?;
        let mut data = cur.into_inner();
        data.extend_from_slice(&a);





        let mut metadata = (data.len() as u32).to_be_bytes().to_vec();
        metadata.extend_from_slice(&data);
        stream.write_all(&metadata).await?;
        stream.flush().await?;
        Ok(())
    }


    pub async fn SessionSetUpResponse1(&mut self, mut stream: &mut TcpStream,) -> anyhow::Result<()> {
        let mut length_header:[u8;4] = [0;4];
        let _ = stream.read_exact(&mut length_header).await?;
        let mut bb:[u8;64] = [0;64];
        let _ = stream.read_exact(&mut bb).await?;
        let mut cur = Cursor::new(bb);
        let mut sessionRespHeader:Header = cur.read_le()?;

        let ssesion_id = sessionRespHeader.session_id;
        let resp_length = u32::from_be_bytes(length_header) as usize;
        //去掉NetBios头之后的长度

        let mut session_resp_header:[u8;2] = [0;2];
        let mut blob_offset:usize = 0;
        let mut blob_length:usize = 0;
        for i in 1..5 {
            let _ = stream.read_exact(&mut session_resp_header).await?;
            if i == 3{
                blob_offset = u16::from_le_bytes(session_resp_header) as usize;

            }else if i ==4 {
                blob_length = u16::from_le_bytes(session_resp_header) as usize;
            }
        }
        let mut start_position:usize = 0;
        if blob_offset > 72 {
            start_position = blob_offset - 72
        }
        let mut secBlobdataTemp: Vec<u8> = vec![0; resp_length - 72];
        //此时的长度是，blob+填充内容的长度，长度值要么和start_positon一致，要么是0，也就是没有填充
        let _ = stream.read_exact(&mut secBlobdataTemp).await?;
        //secBlob即为最终的blob_data，接下来进行asn1解析，获取NTLMSSP的内容
        let secBlobData = &secBlobdataTemp[start_position..];
        // println!("secBlob: {:?}", hex::encode(&secBlob));
        // let sss = secBlob.clone();
        // let cc:SecBlob2 = der::decode(&sss)?;
        // println!("cc: {:?}", cc);


        let secBlob:SecBlob2 = der::decode(secBlobData)?;
        let secProvider = secBlob.secPro.data.unwrap().to_vec();
        self.sesionSetup1RespHeader = sessionRespHeader;
        self.sessionSetup1RespSecProvider = secProvider;

        Ok(())
    }
}


#[derive(AsnType, Decode, Encode)]
#[rasn(tag(application, 0))]
pub(crate) struct SecBlob1 {
    pub Oid: Option<ObjectIdentifier>,

    #[rasn(tag(explicit(0)))]
    pub(crate) negoInit: NegoInit



}

impl SecBlob1 {
    pub fn new() -> anyhow::Result<Self> {
        let oidString1 = Oid::new(OID1).unwrap();
        let oidString2 = Oid::new(OID2).unwrap();
        let s = SecBlob1 {
            Oid: Some(ObjectIdentifier::from(oidString1)),
            negoInit: NegoInit {
                mechTypes: MechTypes {
                    mechType: Some(ObjectIdentifier::from(oidString2)),
                },
                mechTokens: MechTokens {
                    data: Some(OctetString::new()),
                }
            }
        };
        Ok(s)
    }
}

#[derive(AsnType, Decode, Encode)]
pub struct NegoInit {
    #[rasn(tag(explicit(0)))]
    pub mechTypes: MechTypes,
    #[rasn(tag(context, 2))]
    pub mechTokens: MechTokens,


}




#[derive(AsnType, Decode, Encode)]
struct MechTypes {

    mechType: Option<ObjectIdentifier>,

}

#[derive(AsnType, Decode, Encode)]
pub struct MechTokens {
    pub data: Option<OctetString>
}

#[derive(BinRead, BinWrite, Debug)]
struct NtmlSecProvider {
    identifier: [u8; 8],
    messageType: [u8; 4],
    negoFlags: [u8; 4],
    domainLen: [u8; 2],
    domainMaxLen: [u8; 2],
    domainOffset: [u8; 4],
    workstationLen: [u8; 2],
    workstationMaxLen: [u8; 2],
    workstationOffset: [u8; 4],
    // #[brw(ignore)]
    #[br(count = u16::from_le_bytes(domainLen))]
    domainName: Vec<u8>,
    // #[brw(ignore)]
    #[br(count = u16::from_le_bytes(workstationLen))]
    workstationName: Vec<u8>,

}

impl SmbOptions2<'_> {
    fn GeneraeSecBlob(&mut self) -> anyhow::Result<(Vec<u8>, u16)> {

        let mut blob = SecBlob1::new()?;

        let f
            = Flags::NEGOTIATE_56BIT
            | Flags::NEGOTIATE_128BIT
            | Flags::NEGOTIATE_TARGET_INFO
            | Flags::NEGOTIATE_NTLM2_KEY
            | Flags::NEGOTIATE_DOMAIN_SUPPLIED
            | Flags::NEGOTIATE_NTLM
            | Flags::REQUEST_TARGET
            | Flags::NEGOTIATE_UNICODE
            ;

        let signature=  *b"NTLMSSP\x00";
        let message_type= 1u32.to_le_bytes();
        let NegotiateFlags = f.bits().to_le_bytes();

        let DomainName = self.Domain.as_bytes().to_vec();
        let DomainName_len = DomainName.len() as u16;
        let Workstation = self.Workstation.to_string().into_bytes();
        let Workstation_len = Workstation.len() as u16;
        let mut a = NtmlSecProvider {
            identifier: *b"NTLMSSP\x00",
            messageType: message_type,
            negoFlags: NegotiateFlags,
            domainLen: DomainName_len.to_le_bytes(),
            domainMaxLen: DomainName_len.to_le_bytes(),
            domainOffset: [0,0,0,0],
            workstationLen: Workstation_len.to_le_bytes(),
            workstationMaxLen: Workstation_len.to_le_bytes(),
            workstationOffset: [0,0,0,0],
            domainName: DomainName,
            workstationName: Workstation,
        };
        let providerLen = 8 + 4 + 4 + 2 + 2 + 4 + 2 + 2 + 4 + DomainName_len + Workstation_len;
        a.workstationOffset = ((providerLen - Workstation_len) as u32).to_le_bytes();
        a.domainOffset = ((providerLen - DomainName_len - Workstation_len) as u32).to_le_bytes();
        let mut c = Cursor::new(Vec::<u8>::new());
        a.write_le(&mut c)?;
        let NTLMSSP_DATA = c.into_inner();



        blob.negoInit.mechTokens.data = Some(OctetString::from(NTLMSSP_DATA));
        let data = der::encode(&blob)?;
        let len = data.len();
        Ok((data, len as u16))
    }
}








#[derive(AsnType, Debug, PartialEq, Encode, Decode, Copy, Clone)]
#[rasn(enumerated)]
enum  ErrCode {
    InitialRequest = 0,

    NtlmChallenge = 1,

    KerberosAuth = 2,


}



#[derive(AsnType, Encode, Decode, Debug, PartialEq)]
#[rasn(tag(explicit(1)))]
struct SecBlob2 {
    // a0 字段：认证机制枚举（上下文特定标签 0）
    #[rasn(tag(context, 0))]
    negReuslt: NegResult,

    // a1 字段：OID（上下文特定标签 1）
    #[rasn(tag(context, 1))]
    supportMech: SuportMech,

    // // a2 字段：NTLM 挑战数据（上下文特定标签 2）
    #[rasn(tag(context, 2))]
    pub secPro: SecProvider,
}

#[derive(AsnType, Encode, Decode, Debug, PartialEq)]
struct NegResult {
    result: ErrCode,
}

#[derive(AsnType, Encode, Decode, Debug, PartialEq)]
struct SuportMech {
    pub oid: Option<ObjectIdentifier>,
}



impl SmbOptions2<'_> {


    pub async fn SessionSetupRequset2(&mut self, mut stream: &mut TcpStream) -> anyhow::Result<()> {
        let credss = ntlmclient::Credentials {
            username: self.User.to_string(),
            password: self.Password.to_string(),
            domain: self.Domain.to_string(),
        };

        let slice: &[u8] = self.sessionSetup1RespSecProvider.as_slice();

        let challenge = ntlmclient::Message::try_from(slice)?;


        let challenge_content = match challenge {
            Message::Challenge(ref c) => c,
            _ => return Err(anyhow!("Invalid challenge message"))
        };
        let mut timestamp:[u8;8] = [0;8];
        for entry in &challenge_content.target_information {
            match entry.entry_type {
                TargetInfoType::Terminator => {}
                TargetInfoType::NtServer => {}
                TargetInfoType::NtDomain => {}
                TargetInfoType::DnsDomain => {}
                TargetInfoType::DnsServer => {}
                TargetInfoType::DnsForest => {}
                TargetInfoType::Flags => {}
                TargetInfoType::Timestamp => {
                    timestamp.copy_from_slice(&(entry.data.clone()));

                }
                TargetInfoType::SingleHost => {}
                TargetInfoType::TargetName => {}
                TargetInfoType::ChannelBindings => {}
                TargetInfoType::Unknown(_) => {}
            }
        }

        let target_info_bytes: Vec<u8> = challenge_content.target_information
            .iter()
            .flat_map(|ie| ie.to_bytes())
            .collect();
        let creds = credss;
        let mut challenge_response = ntlmclient::respond_challenge_ntlm_v2(
            challenge_content.challenge,
            &target_info_bytes,
            ntlmclient::get_ntlm_time(),
            &creds,
            self.hash
        );
        //根据golang库，此项为0
        challenge_response.session_key = vec![];



        let auth_flags
            = ntlmclient::Flags::NEGOTIATE_56BIT
            | ntlmclient::Flags::NEGOTIATE_128BIT
            | ntlmclient::Flags::NEGOTIATE_TARGET_INFO
            | ntlmclient::Flags::NEGOTIATE_NTLM2_KEY
            | ntlmclient::Flags::NEGOTIATE_DOMAIN_SUPPLIED
            | ntlmclient::Flags::NEGOTIATE_NTLM
            | ntlmclient::Flags::REQUEST_TARGET
            | ntlmclient::Flags::NEGOTIATE_UNICODE
            ;
        let auth_msg = challenge_response.to_message(
            &creds,
            self.Workstation.clone(),
            auth_flags,
        );

        let new_auth_msg_bytes = manual_auth_msg(auth_msg.clone());

        let mut newheader = Header::new();
        newheader.credit_charge = 1;
        newheader.command = 1;
        newheader.credits = 127u16;
        newheader.message_id = 2;
        newheader.session_id = self.sesionSetup1RespHeader.session_id;

        let mut req2 = SessionSetup1Req {
            Header: newheader,
            StructureSize: 25,
            Flags: 0x00,
            SecurityMode: 1,
            Capabilities: 0,
            Channel: 0,
            SecurityBufferOffset: 0,
            SecurityBufferLength: 0,
            PreviousSessionID: 0,

        };
        req2.SecurityBufferLength = (new_auth_msg_bytes.len() + 16 ) as u16;
        req2.SecurityBufferOffset = 0x58;


        let mut cur = Cursor::new(Vec::<u8>::new());
        req2.write_le(&mut cur)?;
        let mut data = cur.into_inner();


        //add security blob
        data.extend_from_slice(generateSecBlob(new_auth_msg_bytes)?.as_slice());


        let mut metadata = (data.len() as u32).to_be_bytes().to_vec();
        metadata.extend_from_slice(&data);
        stream.write_all(&metadata.clone()).await?;
        //flush
        stream.flush().await?;




        Ok(())
    }
}


fn manual_auth_msg(m:Message) -> Vec<u8>{
    match m {
        Message::Authenticate(a) => {

            let lm_resp = a.lm_response.clone();
            let ntlm_resp = a.ntlm_response.clone();
            let mut domain_resp = a.domain_name;

            let user_resp = a.user_name;
            // println!("username : {:?}", user_resp);

            let host_resp = a.workstation_name;

            let flags_resp = a.flags;

            // println!("os_version is: {:?}", a.os_version);
            let NTLMSSP_header: [u8; 8] = [
                0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00
            ];
            let NTMLSSP_type: [u8; 4] = [
                0x03, 0x00, 0x00, 0x00
            ];
            //lm_resp
            let lm_resp_len = lm_resp.len() as u16;
            let lm_resp_max_len = lm_resp.len() as u16;

            //ntlm_resp
            let ntlm_resp_len = ntlm_resp.len() as u16;
            let ntlm_resp_max_len = ntlm_resp.len() as u16;
            //domain_name
            let doamin_resp_len = (domain_resp.len()* 2) as u16;
            let doamin_resp_max_len = (domain_resp.len()* 2) as u16;

            //username
            let user_resp_len = (user_resp.len()* 2)  as u16;
            let user_resp_max_len = (user_resp.len() *2) as u16;

            //hostname
            let host_resp_len = (host_resp.len()* 2) as u16;
            let host_resp_max_len = (host_resp.len() * 2) as u16;

            //session_key
            let session_key:[u8;8] = [0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00];
            let flags_resp = a.flags.bits().to_ne_bytes();
            let all_length1:usize =  8 + 4 + 8 + 8 + 8 + 8 + 8 + 8 +4 ;//这是各项属性的len + maxlen + offsec 这三个字段长度的值
            let all_length2:usize = doamin_resp_len as usize + user_resp_len as usize +
                host_resp_len as usize + lm_resp_len as usize + ntlm_resp_len as usize;
            let all_length = all_length1 + all_length2;
            // println!("all length: {:?}", all_length);
            let ntlm_resp_offsec = (all_length as u16 - ntlm_resp_len) as u32;
            let lm_resp_offsec = ntlm_resp_offsec - 24u32;
            let host_resp_offsec = lm_resp_offsec - (host_resp_len as u32);
            let user_resp_offsec = host_resp_offsec - (user_resp_len as u32);
            let doamin_resp_offsec =user_resp_offsec - (doamin_resp_len as u32);
            //开始添加
            let mut final_resp = Vec::new();
            final_resp.extend_from_slice(&NTLMSSP_header);

            final_resp.extend_from_slice(&NTMLSSP_type);

            // lm response
            final_resp.extend_from_slice(&lm_resp_len.to_le_bytes());
            final_resp.extend_from_slice(&lm_resp_max_len.to_le_bytes());
            final_resp.extend_from_slice(&lm_resp_offsec.to_le_bytes());

            final_resp.extend_from_slice(&ntlm_resp_len.to_le_bytes());
            final_resp.extend_from_slice(&ntlm_resp_max_len.to_le_bytes());
            final_resp.extend_from_slice(&ntlm_resp_offsec.to_ne_bytes());

            final_resp.extend_from_slice(&doamin_resp_len.to_le_bytes());
            final_resp.extend_from_slice(&doamin_resp_max_len.to_le_bytes());
            final_resp.extend_from_slice(&doamin_resp_offsec.to_ne_bytes());


            final_resp.extend_from_slice(&user_resp_len.to_le_bytes());
            final_resp.extend_from_slice(&user_resp_max_len.to_le_bytes());
            final_resp.extend_from_slice(&user_resp_offsec.to_ne_bytes());


            final_resp.extend_from_slice(&host_resp_len.to_le_bytes());
            final_resp.extend_from_slice(&host_resp_max_len.to_le_bytes());
            final_resp.extend_from_slice(&host_resp_offsec.to_le_bytes());


            final_resp.extend_from_slice(&session_key);

            final_resp.extend_from_slice(&flags_resp);

            final_resp.extend_from_slice(&string_to_utf16_bytes(domain_resp.as_str()));
            final_resp.extend_from_slice(&string_to_utf16_bytes(user_resp.as_str()));

            final_resp.extend_from_slice(&string_to_utf16_bytes(host_resp.as_str()));
            final_resp.extend_from_slice(&lm_resp);

            final_resp.extend_from_slice(&ntlm_resp);
            final_resp
        }
        _ => {
            vec![]
        }
    }

}

fn generateSecBlob(d: Vec<u8>) -> anyhow::Result<Vec<u8>> {

    let s = SecBlob {
        secPro: SecProvider {
            data: Some(OctetString::from(d))
        },
    };
    let data = der::encode(&s)?;


    Ok(data)
}

#[derive(AsnType, Encode, Decode, Debug, PartialEq)]
#[rasn(tag(explicit(1)))]
struct SecBlob {
    #[rasn(tag(context, 2))]
    pub secPro: SecProvider,



}

#[derive(AsnType, Encode, Decode, Debug, PartialEq)]
struct SecProvider {
    pub data: Option<OctetString>,
}