use asn1_rs::{FromDer, GeneralString, Oid, Sequence};





const NTLMSSP: &str = "1.3.6.1.4.1.311.2.2.10";
const SPNEGO_OID: &str = "1.3.6.1.5.5.2";



struct blob_field {
    MechTypes: Vec<String>,
    Oid: Vec<String>,

}
impl blob_field {
    
    
    fn addMechType(&mut self, mechtype:String) {
        self.MechTypes.push(mechtype);
        
    }
    fn addOid(&mut self, oid:String) {
        self.Oid.push(oid);
    }
}



pub fn parse_security_blob(d: &[u8]) {
    
    

    let packet_bytes: [u8; 120] = [
        0x60, 0x76, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05,
  0x05, 0x02, 0xa0, 0x6c, 0x30, 0x6a, 0xa0, 0x3c,
  0x30, 0x3a, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
  0x01, 0x82, 0x37, 0x02, 0x02, 0x1e, 0x06, 0x09,
  0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02,
  0x02, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
  0x12, 0x01, 0x02, 0x02, 0x06, 0x0a, 0x2a, 0x86,
  0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x03,
  0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
  0x37, 0x02, 0x02, 0x0a, 0xa3, 0x2a, 0x30, 0x28,
  0xa0, 0x26, 0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f,
  0x64, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x64, 0x5f,
  0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31,
  0x37, 0x38, 0x40, 0x70, 0x6c, 0x65, 0x61, 0x73,
  0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65,
      ];
    
    let mut single_blob = blob_field{
        Oid : vec![],
        MechTypes : vec![]
    };
    parse_asn1_node(&mut single_blob,2,&packet_bytes);
    // single_blob.addMechType("asdasdas".to_string());
    // single_blob.addMechType("asdasdas".to_string());
    // single_blob.addMechType("asdasdas".to_string());
    // println!("{:?}", single_blob.Oid);
    for i in single_blob.Oid.iter(){
        println!("{:?}", i)
    }

    //   let (rem, obj3) = GeneralString::from_der(&packet_bytes).expect("parsing failed");

}


fn parse_asn1_node(blob: &mut blob_field, length: usize, data: &[u8]) {
    if data.len() < 1{
        return;
    }

    // println!("Got Node, tag: {:?}", data[0]);
    
    let mut offsec = length;
    let ttag = data[0];
    if ttag != 0x06 && ttag != 0x30 && ttag != 0x1b {
        let newData = &data[offsec..data.len()];

        // println!("Tag: {:02x}", ttag);
        // println!("Length: {}", length);
        // println!("Value: {:?}", newData.len());
        // println!("newData: {:?}", newData);
        // println!("------------------------");
        nmsl( blob,&newData);
    }else {
        nmsl(blob,&data);
    }
}

fn nmsl(blob: &mut blob_field, bytes: &[u8]) {
    if bytes.len() < 1{
        return;
    }
    let ttag = bytes[0];
    if  ttag == 0x1b {
        // println!("Got Gstring");
        let dataLength = bytes[1];
        // println!("dataLength: {:?}", dataLength);
        // println!("data is : {:?}", &bytes[0..dataLength as usize + 2 ]);
        let (_, data) = GeneralString::from_der(&bytes[0..dataLength as usize + 2]).expect("parsing failed");
        // println!("Gstring is : {:?}", data.string());
        // println!("newData : {:?}", &bytes[dataLength as usize + 2..bytes.len()]);
        // println!("------------------------");
        parse_asn1_node(blob,2, &bytes[dataLength as usize + 2..bytes.len()]);
    }else if ttag == 0x06 {
        // println!("Got Oid");
        let dataLength = bytes[1];
        // println!("dataLength: {:?}", dataLength);
        // println!("data is : {:?}", &bytes[0..dataLength as usize + 2 ]);
        let (_, data) = Oid::from_der(&bytes[0..dataLength as usize + 2]).expect("parsing failed");
        // println!("Oid is : {:?}", data.to_string());
        blob.addOid(data.to_string());
        // println!("newData : {:?}", &bytes[dataLength as usize + 2..bytes.len()]);
        // println!("------------------------");
        parse_asn1_node(blob,2, &bytes[dataLength as usize + 2..bytes.len()]);
    }else if ttag == 0x30 {
        let bytesLen = bytes.len();
        // println!("Got Sequence");
        let dataLength = bytes[1];
        if dataLength as usize != bytesLen -2 {
            // println!("emm");
            parse_asn1_node(blob,2, &bytes[dataLength as usize + 2..bytesLen]);
        }
        // println!("dataLength: {:?}", dataLength);
        let (_, data) = Sequence::from_der(&bytes[0..dataLength as usize + 2]).expect("parsing failed");
        // println!("Sequence is : {:?}", data.content);
        // println!("DataContent : {:?}", data.content);
        // println!("------------------------");
        
        // println!("qq");
        parse_asn1_node(blob,2, &data.content);
        
    }else {
        parse_asn1_node(blob,2, &bytes);
    }
}