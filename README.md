# smb2-rs

这是一个用于Smb2.1 协议认证的库。

## 0x01 说明

此库是纯rust手搓的，Linux/Windows都兼容且不依赖lib-smbclient的C库，目前在Windows7、Windows server 2008、Windows server 2012、Windows server 2016以及Windows 10上测试通过，samba没测。


## 0x02 使用方法

见[example/main.rs](example/main.rs)






## 0x03 下一步计划

|     序号     |             说明             | 进度 |
| :----------: |:--------------------------:| :--: |
|    smb v1    |    Windows server 2003     |  ×   |
|    smb v3    | Windows 10 or server 2016+ |  ×   |
| Tree Connect |            ...             |  ×   |
|     PTH      |            ...             |  ×   |

## 0x04 免责声明

它只能实现认证，旨在方便网络安全行业的从业人员/学生进行学习和研究，基于此库开发的任何恶意工具或检测出的样本，均和作者没有任何关系。
