use smb2_rs::{ SmbOptions};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut options = SmbOptions::new();
    options.Workstation = "nmslwsnd";
    options.Domain = "corp";
    options.Host = "192.168.132.156";
    options.Port = "445";
    options.timeout = 0;
    options.User = "administrator";
    options.Password = "test";

    let result = options.Conn().await;
    match result {
        Ok(r) => {
            if r.isAuthenticated {
                println!("Authenticated");
                println!("status_code: {}", r.StatusCode);
            }else {
                println!("Not Authenticated");
                println!("status_code: {}", r.StatusCode);
            }
        }
        Err(e) => {
            println!("{}", e.to_string());
        }
        
    }
    

    Ok(())
}