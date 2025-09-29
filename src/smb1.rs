use std::{format, println};
use std::io::Cursor;
use std::time::Duration;
use anyhow::anyhow;
use binrw::{BinRead, BinReaderExt, BinWrite};
use ntlmclient::{Flags, Message};
use rasn::{der, AsnType, Decode, Encode, Encoder, Decoder};
use rasn::prelude::{ObjectIdentifier, OctetString, Oid};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use bitflags::bitflags;
use crate::error::{IsAuthenticated, SmbError, SmbResult};
use crate::smb2::SmbInfo;

pub(crate) struct SmbOptions1<'a> {
    pub Host : &'a str,
    pub Port : &'a str,
    pub User:        &'a str,
    pub Domain:      &'a str,
    pub Workstation: &'a str,
    pub Password:    &'a str,
    pub timeout: u16,
    pub negoInfo : NegoInfo,
    pub(crate) hash: [u8; 16],


}

pub struct NegoInfo {
    pub pid: u16,
    pub challenge: [u8; 8],
    pub userid: u16,
    pub targetinfo: Vec<u8>,
}


#[derive(BinRead, BinWrite, Debug)]
pub struct smb1Header {
    pub(crate) serverComponent: [u8; 4],
    pub(crate) command: u8,
    pub status: [u8; 4],
    pub(crate) flags: u8,
    pub(crate) flags2: [u8; 2],
    pub(crate) processidHigh: [u8; 2],
    pub(crate) signature: [u8; 8],
    pub(crate) reserved: [u8; 2],
    pub(crate) treeId: [u8; 2],
    pub(crate) processId: [u8; 2],
    pub(crate) userId: [u8; 2],
    pub(crate) mutiplex: [u8; 2],



}



bitflags::bitflags! {
    pub struct SmbHeaderFlags: u8 {
        const LOCK_AND_READ_OK        = 0x01; // 支持 Lock&Read 命令
        const BUF_AVAIL               = 0x02; // 缓冲区大小可用（基本废弃）
        const CASELESS_PATHNAMES      = 0x08; // 不区分大小写路径
        const CANONICALIZED_PATHS     = 0x10; // 使用规范路径格式
        const OPLOCK                  = 0x20; // 支持 Opportunistic Lock
        const OPBATCH                 = 0x40; // 支持 Batch Oplock
        const REPLY                   = 0x80; // 表示此 SMB 消息为响应
    }
}



bitflags::bitflags! {
    //from impacket
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SmbHeaderFlags2: u16 {
        const FLAGS2_LONG_NAMES                       = 0x0001;
        const FLAGS2_EAS                              = 0x0002;
        const FLAGS2_SMB_SECURITY_SIGNATURE           = 0x0004;
        const FLAGS2_IS_LONG_NAME                     = 0x0040;
        const FLAGS2_DFS                              = 0x1000;
        const FLAGS2_PAGING_IO                        = 0x2000;
        const FLAGS2_NT_STATUS                        = 0x4000;
        const FLAGS2_UNICODE                          = 0x8000;
        const FLAGS2_COMPRESSED                       = 0x0008;
        const FLAGS2_SMB_SECURITY_SIGNATURE_REQUIRED  = 0x0010;
        const FLAGS2_EXTENDED_SECURITY                = 0x0800;
    }
}





bitflags::bitflags! {
    //from impacket
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SmbBodyCapabilities: u32 {
        const CAP_RAW_MODE                            = 0x00000001;
        const CAP_MPX_MODE                            = 0x0002;
        const CAP_UNICODE                             = 0x0004;
        const CAP_LARGE_FILES                         = 0x0008;
        const CAP_EXTENDED_SECURITY                   = 0x80000000;
        const CAP_USE_NT_ERRORS                       = 0x40;
        const CAP_NT_SMBS                             = 0x10;
        const CAP_LARGE_READX                         = 0x00004000;
        const CAP_LARGE_WRITEX                        = 0x00008000;
        const CAP_RPC_REMOTE_APIS                     = 0x20;
    }
}











impl SmbOptions1<'_> {

    pub fn New() -> Self {
        let s = SmbOptions1 {
            Host: "",
            Port: "",
            User: "",
            Domain: "",
            Workstation: "",
            Password: "",
            timeout: 0,
            negoInfo: NegoInfo {
                pid: 0,
                challenge: [0u8; 8],
                userid: 0,
                targetinfo: vec![],
            },
            hash: [0u8; 16],
        };
        s
    }



    pub async fn Connect(&mut self, mut t: &mut TcpStream) -> anyhow::Result<SmbInfo> {
        // let target = format!("{}:{}", self.Host, self.Port);
        // //get nego req
        // let negoReq = self.GetNegoMessage()?;
        // let len = negoReq.len();
        // let mut r1 = (len as u32).to_be_bytes().to_vec();
        // r1.extend_from_slice(&negoReq);




        //TODO: parse nego resp, Judge nego result

        //get session setup req1
        let r2 = self.GetSetupMessage1()?;
        let len = r2.len();
        let mut h2 = (len as u32).to_be_bytes().to_vec();
        h2.extend_from_slice(&r2);
        t.write_all(&h2).await?;
        t.flush().await?;

        //parse session setup response1, get challenge, userID and target info
        self.GetSetupResponse1(&mut t).await?;


        //send session setup request2
        let r3 = self.GetSetupRequest2()?;
        let len = r3.len();
        let mut h3 = (len as u32).to_be_bytes().to_vec();
        h3.extend_from_slice(&r3);

        t.write_all(&h3).await?;
        t.flush().await?;

        let login_result = self.GetsessionSetupResp2(&mut t).await?;
        let r = SmbInfo{
            isAuthenticated: IsAuthenticated(login_result),
            StatusCode: format!("{:#010x}", login_result),
        };
        t.shutdown().await?;
        Ok(r)
    }
}


pub(crate) const  Dialects_smbv1: [u8; 23] = [
    0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30,
    0x2e, 0x31, 0x32, 0x00, 0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30,
    0x30, 0x32, 0x00
];





#[derive(BinRead, BinWrite, Debug)]
pub struct NegoReqBody {
    pub(crate) wordCount: u8,
    pub(crate) ByteCount: [u8;2],
    pub(crate) data: [u8; 23],

}

#[derive(BinRead, BinWrite, Debug)]
pub struct NegoRequest {
    pub(crate) header: smb1Header,
    pub(crate) nego: NegoReqBody,
}


impl SmbOptions1<'_> {

}

impl SmbOptions1<'_> {
    pub fn GetSetupMessage1(&mut self) -> anyhow::Result<Vec<u8>> {

        let f1 =
            SmbHeaderFlags::CANONICALIZED_PATHS | SmbHeaderFlags::CASELESS_PATHNAMES;
        let f2 = SmbHeaderFlags2::FLAGS2_LONG_NAMES
            | SmbHeaderFlags2::FLAGS2_EXTENDED_SECURITY
            | SmbHeaderFlags2::FLAGS2_NT_STATUS;
        let mut h = smb1Header {
            serverComponent: [0xff, 0x53, 0x4d, 0x42],
            command: 0x73,
            status: [0, 0, 0, 0],
            flags: f1.bits(),
            flags2: f2.bits().to_le_bytes(),
            processidHigh: [0u8; 2],
            signature: [0u8; 8],
            reserved: [0u8; 2],
            treeId: [0xff; 2],
            processId: [0u8; 2],
            userId: [0u8; 2],
            mutiplex: [0u8; 2],
        };
        h.processId = self.negoInfo.pid.to_le_bytes();
        h.treeId = 65535u16.to_le_bytes();
        h.mutiplex = 0u16.to_le_bytes();

        let mut f3 =
            SmbBodyCapabilities::CAP_EXTENDED_SECURITY
                | SmbBodyCapabilities::CAP_UNICODE
                | SmbBodyCapabilities::CAP_LARGE_READX
                | SmbBodyCapabilities::CAP_LARGE_WRITEX
                | SmbBodyCapabilities::CAP_USE_NT_ERRORS;
        // | SmbBodyCapabilities::CAP_NT_SMBS;

        let blob = GeneraeSecBlob1()?;
        let body = SessionSetup1ReqBody {
            wordCount: 12,
            andxCommand: 0xff,
            reserved: 0,
            andxOffset: [0; 2],
            maxBuffer: 61440u16.to_le_bytes(),
            maxMpxCount: 2u16.to_le_bytes(),
            vcNum: [0x01, 0x00],
            sessionKey: [0u8; 4],
            secBlobLength: blob.1.to_le_bytes(),
            reserved2: [0u8; 4],
            capabilities: f3.bits().to_le_bytes(),
            byteCount: (blob.1 + 10 + 1).to_le_bytes() ,
            secBlob: blob.0,
            nativeOS: [0x55, 0x6e, 0x69, 0x78, 0x00],
            lanManager: [0x53, 0x61, 0x6d, 0x62, 0x61, 0x00],
        };



        let r = SessionSetupRequest1 {
            header: h,
            body: body,
        };
        let mut cur = Cursor::new(Vec::<u8>::new());
        r.write_le(&mut cur)?;





        Ok(cur.into_inner())
    }

    pub async fn GetSetupResponse1(&mut self, mut stream: &mut TcpStream) -> anyhow::Result<()> {
        let mut qq = [0u8; 4];
        stream.read_exact(&mut qq).await?;
        let res1Len = u32::from_be_bytes(qq.try_into().unwrap());
        let mut body:Vec<u8> = Vec::with_capacity(res1Len as usize);
        stream.read_buf(&mut body).await?;
        let mut cur = Cursor::new(body.clone());
        let resp:SessionSetupResponse1 = cur.read_le()?;

        // println!("version: {:?}", String::from_utf8(resp.body.osVersion).unwrap_or("".into()));
        //
        // println!("{:?}", resp);
        let provider = ParseSecBlob(resp.body.secBlob.clone())?;

        let c = ntlmclient::Message::try_from(provider.as_slice())?;
        // println!("challenge: {:x?}", c);
        let (challenge, targetinfo) = match c {

            Message::Challenge(challenge) => {
                let target_info_bytes: Vec<u8> = challenge.target_information
                    .iter()
                    .flat_map(|ie| ie.to_bytes())
                    .collect();
                (challenge.challenge, target_info_bytes)
            }
            _ => {
                Err(anyhow::anyhow!("Unknown challenge"))?
            }


        };

        let userid = u16::from_le_bytes(resp.header.userId);
        self.negoInfo.userid = userid;
        self.negoInfo.challenge = challenge;
        self.negoInfo.targetinfo = targetinfo;
        Ok(())

    }

    pub fn GetSetupRequest2(&mut self) -> anyhow::Result<Vec<u8>> {
        let c = self.negoInfo.challenge;
        let u = self.negoInfo.userid;
        let t = self.negoInfo.targetinfo.clone();
        let f1 =
            SmbHeaderFlags::CANONICALIZED_PATHS | SmbHeaderFlags::CASELESS_PATHNAMES;
        let f2 = SmbHeaderFlags2::FLAGS2_LONG_NAMES
            | SmbHeaderFlags2::FLAGS2_EXTENDED_SECURITY
            | SmbHeaderFlags2::FLAGS2_NT_STATUS;
        let pid:u16 = 54321;
        let mut h = smb1Header {
            serverComponent: [0xff, 0x53, 0x4d, 0x42],
            command: 0x73,
            status: [0, 0, 0, 0],
            flags: f1.bits(),
            flags2: f2.bits().to_le_bytes(),
            processidHigh: [0u8; 2],
            signature: [0u8; 8],
            reserved: [0u8; 2],
            treeId: [0xff; 2],
            processId: pid.to_le_bytes(),
            userId: [0u8; 2],
            mutiplex: [0u8; 2],
        };
        h.processId = pid.to_le_bytes();
        h.treeId = 65535u16.to_le_bytes();
        h.mutiplex = 0u16.to_le_bytes();
        h.userId = u.to_le_bytes();

        let mut f3 =
            SmbBodyCapabilities::CAP_EXTENDED_SECURITY
                | SmbBodyCapabilities::CAP_UNICODE
                | SmbBodyCapabilities::CAP_LARGE_READX
                | SmbBodyCapabilities::CAP_LARGE_WRITEX
                | SmbBodyCapabilities::CAP_USE_NT_ERRORS;

        let blob = self.GeneraeSecBlob2()?;
        let body = SessionSetup1ReqBody {
            wordCount: 12,
            andxCommand: 0xff,
            reserved: 0,
            andxOffset: [0; 2],
            maxBuffer: 61440u16.to_le_bytes(),
            maxMpxCount: 2u16.to_le_bytes(),
            vcNum: [0x01, 0x00],
            sessionKey: [0u8; 4],
            secBlobLength: blob.1.to_le_bytes(),
            reserved2: [0u8; 4],
            capabilities: f3.bits().to_le_bytes(),
            byteCount: (blob.1 + 11).to_le_bytes() ,
            secBlob: blob.0,
            nativeOS: [0x55, 0x6e, 0x69, 0x78, 0x00],
            lanManager: [0x53, 0x61, 0x6d, 0x62, 0x61, 0x00],
        };



        let r = SessionSetupRequest1 {
            header: h,
            body: body,
        };
        let mut cur = Cursor::new(Vec::<u8>::new());
        r.write_le(&mut cur)?;


        Ok(cur.into_inner())
    }

    pub fn GeneraeSecBlob2(&mut self) -> anyhow::Result<(Vec<u8>, u16)> {
        let c = self.negoInfo.challenge;
        let t = self.negoInfo.targetinfo.clone();
        let mut blob = SecBlob3 {
            negReuslt: NegResult {
                result: ErrCode::NtlmChallenge,
            },
            secPro: SecProvider {
                data: None
            },
        };
        let mut Domain = self.Domain;
        let mut Workstation = self.Workstation;
        let mut user = self.User;
        let mut pass = self.Password;
        let creds = ntlmclient::Credentials {
            username: user.to_string(),
            password: pass.to_string(),
            domain: Domain.to_string(),
        };
        let f
            = Flags::NEGOTIATE_56BIT
            | Flags::NEGOTIATE_128BIT
            | Flags::NEGOTIATE_TARGET_INFO
            | Flags::NEGOTIATE_KEY_EXCHANGE
            | Flags::NEGOTIATE_NTLM2_KEY
            | Flags::REQUEST_TARGET
            | Flags::NEGOTIATE_UNICODE
            ;
        let mut challenge_response = ntlmclient::respond_challenge_ntlm_v2(
            c,
            t.as_slice(),
            ntlmclient::get_ntlm_time(),
            &creds,
            self.hash
        );

        let (Domain, Workstation, User) = match challenge_response.to_message(&creds, Workstation, f) {
            Message::Authenticate(a) => {
                let d = a.domain_name.clone();
                let w = a.workstation_name.clone();
                let u = a.user_name.clone();
                (d, w, u)


            }
            _ => {
                return Err(anyhow!("nmsl"))
            }
        };


        let lanResp = challenge_response.lm_response;
        let ntlmResp = challenge_response.ntlm_response;
        let lanRespLen = lanResp.len() as u16;
        let ntlmRespLen = ntlmResp.len() as u16;
        let message_type= 3u32.to_le_bytes();
        let NegotiateFlags = f.bits().to_le_bytes();

        let DomainName = string_to_utf16_bytes(Domain.as_str());
        let DomainName_len = DomainName.len() as u16;
        let Workstation = string_to_utf16_bytes(Workstation.as_str());
        let Workstation_len = Workstation.len() as u16;

        let UserName = string_to_utf16_bytes(User.as_str());
        let UserLen = UserName.len() as u16;
        let UserMaxLen = UserName.len() as u16;


        let mut a = NtmlSecProvider2 {
            identifier: *b"NTLMSSP\x00", //8
            messageType: message_type, //8
            lanrespLen: lanRespLen.to_le_bytes(), //24
            lanrespMaxLen: lanRespLen.to_le_bytes(),// 24
            lanrespMaxOffset: [0u8; 4], //4
            ntlmrespLen: ntlmRespLen.to_le_bytes(),
            ntlmrespMaxLen: ntlmRespLen.to_le_bytes(),
            ntlmrespMaxOffset: [0u8; 4],//4
            negoFlags: NegotiateFlags, //4
            sessionKey: [0u8;8].to_vec(),// 16
            domainLen: DomainName_len.to_le_bytes(),
            domainMaxLen: DomainName_len.to_le_bytes(),
            domainOffset: [0,0,0,0],
            userLen: UserLen.to_le_bytes(),
            userMaxLen: UserMaxLen.to_le_bytes(),
            userOffset: [0u8; 4],
            workstationLen: Workstation_len.to_le_bytes(),
            workstationMaxLen: Workstation_len.to_le_bytes(),
            workstationOffset: [0,0,0,0],
            domainName: DomainName,
            user: UserName,
            workstationName: Workstation,
            lanResp: lanResp,
            ntlmResp: ntlmResp,


        };


        let all_length1:usize =  8 + 4 + 8 + 8 + 8 + 8 + 8 + 8 +4 ;//这是各项属性的len + maxlen + offsec 这三个字段长度的值
        let all_length2:usize = DomainName_len as usize + UserLen as usize +
            Workstation_len as usize + lanRespLen as usize + ntlmRespLen as usize;
        let all_length = all_length1 + all_length2;
        let ntlm_resp_offsec = (all_length as u16 - ntlmRespLen) as u32;
        let lm_resp_offsec = ntlm_resp_offsec - 24u32;
        let host_resp_offsec = lm_resp_offsec - (Workstation_len as u32);
        let user_resp_offsec = host_resp_offsec - (UserLen as u32);
        let doamin_resp_offsec =user_resp_offsec - (DomainName_len as u32);
        a.domainOffset = doamin_resp_offsec.to_le_bytes();
        a.userOffset = user_resp_offsec.to_le_bytes();
        a.workstationOffset = host_resp_offsec.to_le_bytes();
        a.lanrespMaxOffset = lm_resp_offsec.to_le_bytes();
        a.ntlmrespMaxOffset = ntlm_resp_offsec.to_le_bytes();


        let mut c = Cursor::new(Vec::<u8>::new());
        a.write_le(&mut c)?;
        let NTLMSSP_DATA = c.into_inner();



        blob.secPro.data = Some(OctetString::from(NTLMSSP_DATA));
        let data = der::encode(&blob)?;
        let len = data.len();
        Ok((data, len as u16))
    }



    pub async fn GetsessionSetupResp2(&mut self, mut stream: &mut TcpStream) -> anyhow::Result<u32> {

        let mut headerLen = [0u8; 4];
        stream.read_exact(&mut headerLen).await?;
        let len = u32::from_be_bytes(headerLen.try_into()?);
        let mut body:Vec<u8> = Vec::with_capacity(len as usize);
        stream.read_buf(&mut body).await?;
        let mut cursor = Cursor::new(body[..32].to_vec());
        let header:smb1Header = cursor.read_be()?;
        let status = u32::from_le_bytes(header.status);
        Ok(status)
    }
}


#[derive(BinRead, BinWrite, Debug)]
pub struct SessionSetupRequest1 {
    header: smb1Header,
    body: SessionSetup1ReqBody

}


// #[derive(BinRead, BinWrite, Debug)]
// pub struct SessionSetupRequest2 {
//     header: Header,
//     body: SessionSetup1ReqBody
// }


#[derive(BinRead, BinWrite, Debug)]
pub struct SessionSetupResponse1 {
    header: smb1Header,
    body: SessionSetup1RespBody

}

#[derive(BinRead, BinWrite, Debug)]
pub struct SessionSetup1ReqBody {
    wordCount: u8,
    andxCommand: u8,
    reserved: u8,
    andxOffset: [u8; 2],
    maxBuffer: [u8; 2],
    maxMpxCount: [u8; 2],
    vcNum: [u8; 2],
    sessionKey: [u8; 4],
    secBlobLength: [u8; 2],
    reserved2: [u8; 4],
    capabilities: [u8; 4],
    #[br(calc = secBlobLength)]
    byteCount: [u8; 2],
    #[br(count = u16::from_le_bytes(secBlobLength))]
    secBlob: Vec<u8>,
    nativeOS: [u8; 5],
    lanManager: [u8; 6],



}






#[derive(BinRead, BinWrite, Debug)]
pub struct SessionSetup1RespBody {
    wordCount: u8,
    andxCommand: u8,
    reserved: u8,
    andxOffset: [u8; 2],
    action: [u8; 2],
    secBlobLength: [u8; 2],
    byteCount: [u8; 2],
    #[br(count = u16::from_le_bytes(secBlobLength))]
    secBlob: Vec<u8>,
    #[br(count = u16::from_le_bytes(byteCount) - u16::from_le_bytes(secBlobLength))]
    osVersion: Vec<u8>



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


const OID1: &[u32] = &[1, 3, 6, 1, 5, 5, 2];
const OID2: &[u32] = &[1, 3, 6, 1, 4, 1, 311, 2, 2, 10];
pub fn GeneraeSecBlob1() -> anyhow::Result<(Vec<u8>, u16)> {
    let Domain = "corp";
    let Workstation = "123";
    let mut blob = SecBlob1::new()?;

    let f
        = Flags::NEGOTIATE_56BIT
        | Flags::NEGOTIATE_128BIT
        | Flags::NEGOTIATE_TARGET_INFO
        | Flags::NEGOTIATE_KEY_EXCHANGE
        | Flags::NEGOTIATE_NTLM
        | Flags::REQUEST_TARGET
        | Flags::NEGOTIATE_UNICODE
        ;

    let message_type= 1u32.to_le_bytes();
    let NegotiateFlags = [0x05, 0x02, 0x88, 0xa0];

    let DomainName = Domain.as_bytes().to_vec();
    let DomainName_len = DomainName.len() as u16;
    let Workstation = Workstation.to_string().into_bytes();
    let Workstation_len = Workstation.len() as u16;
    let mut a = NtmlSecProvider1 {
        identifier: *b"NTLMSSP\x00",
        messageType: message_type,
        negoFlags: NegotiateFlags,
        domainName: [0; 8],
        workstationName: [0; 8],
    };
    let mut c = Cursor::new(Vec::<u8>::new());
    a.write_le(&mut c)?;
    let NTLMSSP_DATA = c.into_inner();



    blob.negoInit.mechTokens.data = Some(OctetString::from(NTLMSSP_DATA));
    let data = der::encode(&blob)?;
    let len = data.len();
    Ok((data, len as u16))
}






pub fn ParseSecBlob(data: Vec<u8>) -> anyhow::Result<Vec<u8>> {

    let res:SecBlob2 = der::decode(&data)?;
    let p = res.secPro.data.unwrap();

    Ok(p.to_vec())
}


#[derive(AsnType, Decode, Encode)]
#[rasn(tag(application, 0))]
struct SecBlob1 {
    pub Oid: Option<ObjectIdentifier>,

    #[rasn(tag(explicit(0)))]
    pub negoInit: NegoInit



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
    pub mechType: Option<ObjectIdentifier>,

}

#[derive(AsnType, Decode, Encode)]
pub struct MechTokens {
    pub data: Option<OctetString>
}

#[derive(BinRead, BinWrite, Debug)]
struct NtmlSecProvider1 {
    identifier: [u8; 8],
    messageType: [u8; 4],
    negoFlags: [u8; 4],
    domainName: [u8; 8],
    workstationName: [u8; 8],

}
#[derive(BinWrite, Debug)]
struct NtmlSecProvider2 {
    identifier: [u8; 8],
    messageType: [u8; 4],
    lanrespLen: [u8; 2],
    lanrespMaxLen: [u8; 2],
    lanrespMaxOffset: [u8; 4],
    ntlmrespLen: [u8; 2],
    ntlmrespMaxLen: [u8; 2],
    ntlmrespMaxOffset: [u8; 4],
    domainLen: [u8; 2],
    domainMaxLen: [u8; 2],
    domainOffset: [u8; 4],
    userLen: [u8; 2],
    userMaxLen: [u8; 2],
    userOffset: [u8; 4],
    workstationLen: [u8; 2],
    workstationMaxLen: [u8; 2],
    workstationOffset: [u8; 4],
    sessionKey: Vec<u8>,
    negoFlags: [u8; 4],
    domainName: Vec<u8>,
    user: Vec<u8>,
    workstationName: Vec<u8>,
    lanResp: Vec<u8>,
    ntlmResp: Vec<u8>,




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
#[rasn(tag(explicit(1)))]
struct SecBlob3 {
    // a0 字段：认证机制枚举（上下文特定标签 0）
    #[rasn(tag(context, 0))]
    negReuslt: NegResult,

    // // a2 字段：NTLM 挑战数据（上下文特定标签 2）
    #[rasn(tag(context, 2))]
    pub secPro: SecProvider,
}

#[derive(AsnType, Encode, Decode, Debug, PartialEq)]
struct NegResult {
    result: ErrCode,
}

#[derive(AsnType, Debug, PartialEq, Encode, Decode, Copy, Clone)]
#[rasn(enumerated)]
enum  ErrCode {
    InitialRequest = 0,

    NtlmChallenge = 1,

    KerberosAuth = 2,


}

#[derive(AsnType, Encode, Decode, Debug, PartialEq)]
struct SuportMech {
    pub oid: Option<ObjectIdentifier>,
}


#[derive(AsnType, Encode, Decode, Debug, PartialEq)]
struct SecProvider {
    pub data: Option<OctetString>,
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