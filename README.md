# smb2-rs

这是一个用于Smb2.1 协议认证的库，它使用纯rust实现，起因是我翻遍了github，并没有发现相关且较为成熟的库，唯一有用的只能工作于3.X，但这样的话它的兼容性就不高了，smb3从server 2016/windows 10引入，那么在那之前的windows就没法搞了，但是截止目前，至少smb 2.1支持从server 2008到2016、windows 7到windows 10，所以有了这个库。


## 0x01 说明

😊此库是纯rust手搓的，Linux/Windows都兼容且不依赖lib-smbclient的C库，目前在Windows7、Windows server 2008、Windows server 2012、Windows server 2016以及Windows 10上测试通过，samba没测。

😊如果有想法可以加入我一起完善。

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

## 0x03 注意

🤖它只能实现认证，旨在方便网络安全行业的从业人员/学生进行学习和研究，没有其他目的，如果你想拿它用来编写自己的开源/闭源工具，那么请点个Star吧。


## 0x04 下一步计划

|     序号     |            说明            | 进度 |
| :----------: | :------------------------: | :--: |
|    smb v1    |    Windows server 2003     |  ×   |
|    smb v3    | Windows 10 or server 2016+ |  ×   |
| Tree Connect |            ...             |  ×   |
|     PTH      |          you know          |  ×   |

## 0x05 免责声明

😡基于此库开发的任何恶意工具或检测出的样本，均和本人没有任何关系。
