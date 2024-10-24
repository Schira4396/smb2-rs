
// use core::str;
// use base64::prelude::{ Engine};


use std::str::{FromStr};

use asn1_rs::nom::number::complete::{u32, u8};
use asn1_rs::{Enumerated, FromDer, OctetString, Oid, OidParseError, ToDer};
use asn1_rs::nom::AsBytes;
use bincode::{Options};
use anyhow::{Result};
use serde::{Deserialize, Serialize, };
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use ntlmclient;
use ntlmclient::{Flags, Message, TargetInfoType};



pub struct SmbOptions<'a> {
    pub Host : &'a str,
    pub Port : &'a str,
    pub User:        &'a str,
    pub Domain:      &'a str,
    pub Workstation: &'a str,
    pub Password:    &'a str,


}
pub struct SmbResult {
    IsAuthenticated: bool,
    pub StatusCode: u32
}
impl SmbResult {
    pub fn IsAuthenticated(&mut self) -> bool {
        match self.StatusCode {
            0 => {
                println!("Status: Success")
            },
            3221225581 => {
                println!("Status: Logon Failure")
            },
            _ => {
                println!("Status: Unknown")
            },
        }
        self.IsAuthenticated = true;
        return self.IsAuthenticated
    }
}



#[tokio::main]
async fn main() -> Result<()> {

    let op = SmbOptions{
        Host:        "192.168.132.173",
        Port:        "445",
        User:        "administrator",
        Domain:      "corp",
        Workstation: "123",
        Password:    "123456",
    };
    let mut result = Conn(op).await?;
    result.IsAuthenticated();
    println!("status_code: {:?}", result.StatusCode);
    Ok(())
}






pub async fn Conn(op:SmbOptions<'_>) -> Result<SmbResult> {

    let credss = ntlmclient::Credentials {
        username: op.User.to_string(),
        password: op.Password.to_string(),
        domain: op.Domain.to_string(),
    };
    let target = op.Host.to_owned() + ":" + &(op.Port);
    println!("target is: {:?}", target);
    let mut stream = TcpStream::connect(target).await?;
    let mut newheader = newHeader();
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


    let serialized_data = bincode::DefaultOptions::new().with_fixint_encoding().with_little_endian().serialize(&req).expect("Serialization failed");
    // let serialized_data = Serializer::SerializeStruct::serialize_struct(self, &req, 9);

    let mut metadata = bincode::DefaultOptions::new().with_fixint_encoding().with_big_endian().serialize(&(serialized_data.len() as u32))?;
    metadata.extend_from_slice(&serialized_data);
    stream.write_all(&metadata).await?;
    stream.flush().await.expect("TODO: panic message");
    let mut res_header:[u8;4] = [0;4];
    let res = stream.read_exact(&mut res_header).await?;
    let body_size = u32::from_be_bytes(res_header) as usize;
    // println!("body_size: {:?}", body_size);
    let mut res_data:Vec<u8> = vec![0; body_size ];
    let _ = stream.read_exact(&mut res_data).await?;
    // println!("res_data: {:?}", res_data);
    let ProtoColID = &res_data[0..4];

    let des_data:Header = bincode::deserialize(&res_data[0..64]).expect("oh??L:");
    // println!("asdsad");
    // println!("qq{:?}", des_data);




    let respLen = res_data.len() - 64;
    ///////////////////////
    //   !!!!需要完善！！！///
    ///////////////////////
    // parse_security_blob(&res_data[64..]);
    // println!("start,,,,");
    // let mut ttt:[u8;100] = [0;100];
    // let x = stream.read_exact(&mut ttt).await?;



    let mut newheader2 = newHeader();
    // newheader.command = command::CommandSessionSetup as u16;

    newheader2.credit_charge = 1;
    newheader2.command = command::CommandSessionSetup as u16;
    newheader2.message_id = des_data.session_id + 1;
    newheader2.session_id = des_data.session_id;





    let f
        = ntlmclient::Flags::NEGOTIATE_56BIT
        | ntlmclient::Flags::NEGOTIATE_128BIT
        | ntlmclient::Flags::NEGOTIATE_TARGET_INFO
        | ntlmclient::Flags::NEGOTIATE_NTLM2_KEY
        | ntlmclient::Flags::NEGOTIATE_DOMAIN_SUPPLIED
        | ntlmclient::Flags::NEGOTIATE_NTLM
        | ntlmclient::Flags::REQUEST_TARGET
        | ntlmclient::Flags::NEGOTIATE_UNICODE
        ;






    let mut k = SessionSetup1Req {
        Header: newheader2,
        StructureSize: 25,
        Flags: 0x00,
        SecurityMode: 1,
        Capabilities: 0,
        Channel: 0,
        SecurityBufferOffset: 88,
        SecurityBufferLength: 0,
        PreviousSessionID: 0,

    };
    // let k_length = bincode::DefaultOptions::new().with_fixint_encoding().with_little_endian().serialize(&k).expect("Serialization failed");



    let (a,b) = generate_session_setup_req1(op.Domain.to_string(),op.Workstation.to_string(), f)?;
    k.SecurityBufferLength = b as u16;
    let mut dd = bincode::DefaultOptions::new().with_fixint_encoding().with_little_endian().serialize(&k).expect("Serialization failed");
    dd.extend_from_slice(&a);







    let mut metadata2 = bincode::DefaultOptions::new().with_fixint_encoding().with_big_endian().serialize(&(dd.len() as u32))?;
    metadata2.extend_from_slice(&dd);
    stream.write_all(&metadata2).await?;
    stream.flush().await.expect("TODO: panic message");
    //先读前4个字节，判断报文长度（后3位）
    // let mut res_data2:Vec<u8> = vec![0; 1];

    let mut length_header:[u8;4] = [0;4];
    let _ = stream.read_exact(&mut length_header).await?;
    let mut bb:[u8;64] = [0;64];
    let res_data2 = stream.read_exact(&mut bb).await?;
    // let res_data222:Vec<u8> = res_data22.into_iter().collect();
    let mut sessionid_data:Header = bincode::deserialize(&bb)?;
    // println!("session_id is: {:?}", sessionid_data.session_id);
    let ssesion_id = sessionid_data.session_id;
    // get_resp2_session_id(res_data2.into_iter().collect());
    // let mut sec_data1:[u8;331] = [0;331];
    let body_length = u32::from_be_bytes(length_header) as usize;
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
    let mut blob_data1: Vec<u8> = vec![0; body_length - 72];
    //此时的长度是，blob+填充内容的长度，长度值要么和start_positon一致，要么是0，也就是没有填充
    let _ = stream.read_exact(&mut blob_data1).await?;
    //blob_data2，即为最终的blob_data，接下来进行asn1解析，获取NTLMSSP的内容
    let blob_data2 = &blob_data1[start_position..];
    let NTLMSSP:Vec<u8> = Parse_NTLMSSP(blob_data2.to_vec())?;
    //--------------------------------
    let slice: &[u8] = &NTLMSSP;

    let challenge = ntlmclient::Message::try_from(slice)
        .expect("decoding challenge message failed");


    let challenge_content = match challenge {
        ntlmclient::Message::Challenge(ref c) => c,
        other => panic!("wrong challenge message: {:?}", other),
    };
    // println!("targetinfo is : {:?}", challenge_content.target_information);
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
        "123",
        auth_flags,
    );

    let new_auth_msg_bytes = manual_auth_msg(auth_msg.clone());
    // let auth_msg_bytes = auth_msg.to_bytes()
    //     .expect("failed to encode NTLM authentication message");

    let mut newheader3 = newHeader();
    newheader3.credit_charge = 1;
    newheader3.command = 1;
    newheader3.credits = 127 as u16;
    newheader3.message_id = 2;
    newheader3.session_id = ssesion_id;

    let mut k3 = SessionSetup1Req {
        Header: newheader3,
        StructureSize: 25,
        Flags: 0x00,
        SecurityMode: 1,
        Capabilities: 0,
        Channel: 0,
        SecurityBufferOffset: 0,
        SecurityBufferLength: 0,
        PreviousSessionID: 0,

    };
    k3.SecurityBufferLength = (new_auth_msg_bytes.len() + 16 ) as u16;
    k3.SecurityBufferOffset = 0x58;
    let mut dd3 = bincode::DefaultOptions::new().with_fixint_encoding().with_little_endian().serialize(&k3)?;
    // let asn1_sequence: [u8; 16] = [0xa1, 0x82, 0x01, 0x8e, 0x30, 0x82, 0x01, 0x8a, 0xa2, 0x82, 0x01, 0x86, 0x04, 0x82, 0x01, 0x82];
    let asn1_sequence  = generate_asn1_header(new_auth_msg_bytes.len() + 16);
    // let asn1_sequence  = [161, 130, 1, 84, 48, 130, 1, 80, 162, 130, 1, 76, 4, 130, 1, 72];
    dd3.extend_from_slice(&asn1_sequence);
    dd3.extend_from_slice(&new_auth_msg_bytes);

    let mut metadata3 = bincode::DefaultOptions::new().with_fixint_encoding().with_big_endian().serialize(&(dd3.len() as u32))?;
    metadata3.extend_from_slice(&dd3);
    stream.write_all(&metadata3.clone()).await?;
    //写入完成后刷新
    stream.flush().await.expect("Unknown Error.");
    //最后一个响应，只需要读取前68个字节，即4 + 64， 64字节即为header
    let mut buffer:Vec<u8> = vec![0;68];
    let _ = stream.read_exact(&mut buffer).await?;
    let f:Header = bincode::deserialize(&buffer[4..])?;
    let login_result = u32::from_le_bytes(f.status.to_ne_bytes());

    stream.shutdown().await?;
    //----------------
    // stream.write_all(&metadata3.clone()).await?;
    // //写入完成后刷新
    // stream.flush().await?;
    // let res4 = stream.read_u32().await?;
    // let mut res_data4 = vec![0;res4 as usize];
    // let _ = stream.read(&mut res_data4).await?;

    let r = SmbResult{
        IsAuthenticated: false,
        StatusCode: login_result,
    };


    Ok(r)
}



fn generate_session_setup_req1(d:String, w:String, f:Flags) -> Result<(Vec<u8>, usize)> {
    let signature=  *b"NTLMSSP\x00";
    let message_type= 1u32.to_le_bytes();
    let NegotiateFlags = f.bits().to_le_bytes();

    let DomainName = d.into_bytes();
    let DomainName_len = DomainName.len() as u16;
    let Workstation = w.to_string().into_bytes();
    let Workstation_len = Workstation.len() as u16;



    // println!("data: {:?}", ntlmsspneg_data);
    let parseOid = Oid::from_str("1.3.6.1.5.5.2").map_err(|e: OidParseError| anyhow::anyhow!("Failed to parse OID: {:?}", e))?;
    let odistr = parseOid.to_der_vec()?;
    let mechidStr = Oid::from_str("1.3.6.1.4.1.311.2.2.10").map_err(|e: OidParseError| anyhow::anyhow!("Failed to parse OID: {:?}", e))?.to_der_vec()?;
    let mut NTLMSSP_DATA = Vec::new();
    let mut NTLMSSP_DATA_len:usize =  8 + 4 + 4 + 2 + 4 + 4 + 2 + 4 + 4 + DomainName_len as usize + Workstation_len as usize;
    NTLMSSP_DATA.extend_from_slice(&signature);
    NTLMSSP_DATA.extend_from_slice(&message_type);
    NTLMSSP_DATA.extend_from_slice(&NegotiateFlags);
    let Workstation_offset =(NTLMSSP_DATA_len as u16 - Workstation_len) as u32;
    let DomainName_offset =(Workstation_offset as u16 - DomainName_len ) as u32 ;
    NTLMSSP_DATA.extend_from_slice(&(DomainName_len.to_le_bytes()));
    NTLMSSP_DATA.extend_from_slice(&(DomainName_len.to_le_bytes()));
    NTLMSSP_DATA.extend_from_slice(&(DomainName_offset.to_le_bytes()));
    NTLMSSP_DATA.extend_from_slice(&(Workstation_len.to_le_bytes()));
    NTLMSSP_DATA.extend_from_slice(&(Workstation_len.to_le_bytes()));
    NTLMSSP_DATA.extend_from_slice(&(Workstation_offset.to_le_bytes()));
    NTLMSSP_DATA.extend_from_slice(&DomainName);
    NTLMSSP_DATA.extend_from_slice(&Workstation);
    let s = asn1_rs::OctetString::from(NTLMSSP_DATA.as_bytes()).to_der_vec()?;
    let mut MechTypes = Vec::new();
    let mut NTLMSSP:Vec<u8> = Vec::new();
    NTLMSSP.extend_from_slice(&[0xa2,s.len() as u8]);
    NTLMSSP.extend_from_slice(&s);
    //
    MechTypes.extend_from_slice(&[0xa0,(mechidStr.len() +2 ) as u8, 0x30, mechidStr.len() as u8]);
    MechTypes.extend_from_slice(&mechidStr);

    // println!("data: {:?}", MechTypes);
    // println!("data: {:?}", NTLMSSP);
    let mut NegInit:Vec<u8> = Vec::new();
    let NegInit_len = NTLMSSP.len() + MechTypes.len();
    NegInit.extend_from_slice(&[0xa0, (NegInit_len + 2) as u8, 0x30, NegInit_len as u8]);
    NegInit.extend_from_slice(&MechTypes);
    NegInit.extend_from_slice(&NTLMSSP);
    // println!("data: {:?}", NegInit);
    // println!("data: {:?}", h11);
    // println!("data: {:?}", odistr);
    let mut  blob_data:Vec<u8> = Vec::new();
    let blob_data_len = NegInit.len() + odistr.len();
    blob_data.extend_from_slice(&[0x60, blob_data_len as u8]);
    blob_data.extend_from_slice(&odistr);
    blob_data.extend_from_slice(&NegInit);
    println!("blob_data, len: {:?}, {:?}",blob_data.len(), blob_data);
    Ok((blob_data.clone() ,blob_data.len().clone()))
}



const DIALECT_SMB_2_1: i32 = 0x0210;

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
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

#[derive(Serialize, Deserialize, Debug)]
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
    CommandLogoff =2,
    CommandTreeConnect=3,
    CommandTreeDisconnect=4,
    CommandCreate=5,
    CommandClose=6,
    CommandFlush=7,
    CommandRead=8,
    CommandWrite=9,
    CommandLock=10,
    CommandIOCtl=11,
    CommandCancel=12,
    CommandEcho=13,
    CommandQueryDirectory=14,
    CommandChangeNotify=15,
    CommandQueryInfo=16,
    CommandSetInfo=17,
    CommandOplockBreak=18
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

fn Parse_NTLMSSP(mut temp:Vec<u8>) -> Result<Vec<u8>>{
    loop {
        if temp.len() == 0 {
            break;
        }

        if temp[0] == TagEnum::TypeEnum as u8 {
            let t = Enumerated::from_der(&temp)?;
            temp = t.0.to_vec();
        }else if temp[0] == TagEnum::TypeOctStr as u8 {
            let t = OctetString::from_der(&temp)?;
            temp = t.1.into_cow().to_vec();
            break;
        }else if temp[0] == TagEnum::TypeOid as u8 {
            let t = Oid::from_der(&temp)?;
            temp = t.0.to_vec();
        }else {
            let (s, b) = asn1_rs::Header::from_der(&temp)?;
            temp = s.to_vec();
        }

    }
    Ok(temp)
}








fn manual_auth_msg(m:Message) -> Vec<u8>{
    match m {
        Message::Authenticate(a) => {

            let lm_resp = a.lm_response.clone();
            let ntlm_resp = a.ntlm_response.clone();
            let hexntlm = hex::encode(&ntlm_resp);
            let mut domain_resp = a.domain_name;

            let user_resp = a.user_name;

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
            return final_resp
        }
        _ => {
            vec![]
        }
    }

}

fn generate_asn1_header(len:usize) -> Vec<u8> {
    // let len:usize = 402;
    let header_len = 16 as usize;
    let mut temp = Vec::new();
    temp.push(0xa1);
    temp.push(0x82);
    let len1 = (len -4) as u16;
    let len2 = len1.to_be_bytes();
    temp.extend_from_slice(&len2);
    temp.push(0x30);
    temp.push(0x82);
    let len1 = (len1 -4) as u16;
    let len2 = len1.to_be_bytes();
    temp.extend_from_slice(&len2);
    temp.push(0xa2);
    temp.push(0x82);
    let len1 = (len1 -4) as u16;
    let len2 = len1.to_be_bytes();
    temp.extend_from_slice(&len2);
    temp.push(0x04);
    temp.push(0x82);
    let len1 = (len1 -4) as u16;
    let len2 = len1.to_be_bytes();
    temp.extend_from_slice(&len2);
    temp
}


fn string_to_utf16_bytes(input: &str) -> Vec<u8> {
    //用于domain、username以及hostname的编码
    // 将字符串编码为 UTF-16
    let utf16_encoded: Vec<u16> = input.encode_utf16().collect();

    // 创建一个 Vec<u8> 用于存储 UTF-16 的字节表示
    let mut utf16_bytes = Vec::new();
    for &code_unit in &utf16_encoded {
        utf16_bytes.push((code_unit & 0xFF) as u8);         // 低字节
        utf16_bytes.push((code_unit >> 8) as u8);         // 高字节
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
#[derive(Serialize, Deserialize, Debug)]
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




fn newHeader() -> Header  {
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



