# smb2-rs

这是一个用于Smb2.1 协议认证的库

## 0x01 说明

此库是纯rust手搓的，Linux/Windows都兼容且不依赖lib-smbclient的C库，目前在Windows7、Windows server 2008、Windows server 2012、Windows server 2016以及Windows 10上测试通过，samba没测。



## 0x02 使用方法



```rust
use smb2_rs::{SmbOptions};
use anyhow::{Result};



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
    let mut result = smb_rs::Conn(op).await?;//result
    let b = result.IsAuthenticated();//bool，方便进行判断
    println!("{:?}, status_code: {:?}",b, result.StatusCode);//...
    Ok(())
}
```


