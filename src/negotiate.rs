use std::io::Cursor;
use tokio::net::TcpStream;
use anyhow::Result;
use binrw::{BinReaderExt, BinWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::{command, Header, NegotiateReq, SecMode, DIALECT_SMB_2_1};

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