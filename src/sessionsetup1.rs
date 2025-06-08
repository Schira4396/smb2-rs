use std::io::Cursor;
use binrw::{BinRead, BinReaderExt, BinWrite};
use ntlmclient::Flags;
use rasn::{AsnType, Decode, Encode, Decoder, Encoder, oid, der};
use rasn::Codec::Der;
use rasn::types::{Enumerated, ObjectIdentifier, Oid};
use rasn::types::OctetString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::{command, Header, SessionSetup1Req, SmbOptions};

const OID1: &[u32] = &[1, 3, 6, 1, 5, 5, 2];
const OID2: &[u32] = &[1, 3, 6, 1, 4, 1, 311, 2, 2, 10];

impl SmbOptions<'_> {
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
            Capabilities: 0,
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
struct SecBlob1 {
    Oid: Option<ObjectIdentifier>,

    #[rasn(tag(explicit(0)))]
    negoInit: NegoInit



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
struct NegoInit {
    #[rasn(tag(explicit(0)))]
    mechTypes: MechTypes,
    #[rasn(tag(context, 2))]
    mechTokens: MechTokens,


}




#[derive(AsnType, Decode, Encode)]
struct MechTypes {

    mechType: Option<ObjectIdentifier>,

}

#[derive(AsnType, Decode, Encode)]
struct MechTokens {
    data: Option<OctetString>
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

impl SmbOptions<'_> {
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


#[derive(AsnType, Encode, Decode, Debug, PartialEq)]
struct SecProvider {
    pub data: Option<OctetString>,
}
