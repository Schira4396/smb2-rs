use std::io::Cursor;
use anyhow::anyhow;
use binrw::BinWrite;
use ntlmclient::{Message, TargetInfoType};
use rasn::{AsnType, Decode, Encode, Decoder, Encoder, der};
use rasn::prelude::OctetString;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use crate::{string_to_utf16_bytes, Header, SessionSetup1Req, SmbOptions};

impl SmbOptions<'_> {


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