
use smb2_rs::SmbOption;




#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut op = SmbOption::new()?;
    op.Host = "192.168.132.185".into();
    op.Port = "445".parse()?;
    op.timeout = 3;
    op.User = "administrator".into();
    op.Password = "123456".into();
    op.Domain = "domain".into();
    op.Workstation = "nmsl".into();

    // If you use this function, it will replace the plaintext password you specified
    op.setHash("32ed87bdb5fdc5e9cba88547376818d4");


    match op.Connect().await {
        Ok(r) => {
            println!("Authenticated");
            println!("{:?}", r.StatusCode)
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    };





    Ok(())
}