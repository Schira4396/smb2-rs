use clap::Parser;
use smb2_rs::SmbOption;




#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let cli = Cli::parse();
    let ipaddress = cli.target.unwrap_or("".to_owned());
    let hash = cli.hash.unwrap_or("".to_owned());
    let username = cli.userName.unwrap_or("".to_owned());
    let password = cli.passWord.unwrap_or("".to_owned());


    let mut op = SmbOption::new()?;
    op.Host = ipaddress.into();
    op.Port = "445".parse()?;
    op.timeout = 3;
    match cli.checkUnauth {
        true => {
            op.User = "".into();
            op.Password = "".into();
        }
        false => {
            op.User = username.into();
            op.Password = password.into();
        }
    }
    op.Domain = "domain".into();
    op.Workstation = "nmsl".into();

    // If you use this function, it will replace the plaintext password you specified
    match hash.is_empty() {
        false => {
            op.setHash(hash.as_str());
        }
        true => {

        }
    }


    match op.Connect().await {
        Ok(r) => {
            if r.isAuthenticated {
                println!("Authenticated");
                println!("status_code: {}", r.StatusCode);
            }else {
                println!("Not authenticated");
                println!("status_code: {}", r.StatusCode);
            }

        }
        Err(e) => {
            println!("Error: {}", e);
        }
    };





    Ok(())
}


#[derive(Parser, Debug)]
#[clap(
    name    = "smbcheck",
    version = "0.1",
    author  = "by Akatsuki",
    term_width = 150,
    next_line_help = true
)]
struct Cli {
    /// Target ip or ips, like 192.168.1.1 or 192.168.1.1/24
    #[clap(short = 't', long = "target", value_name = "TARGET", help = "Target ip address, like 192.168.1.1", required = true)]
    target: Option<String>,


    /// When using the rdp protocol, load the NTLM HASH obtained by dumping
    #[clap(long = "hash", value_name = "NTLM-HASH", help = "When using the rdp protocol, load the NTLM HASH obtained by dumping")]
    hash: Option<String>,



    #[clap(short = 'u', value_name = "USERNAME", help = "UserName, AccountName")]
    userName: Option<String>,

    #[clap(short = 'p', value_name = "PASSWORD", help = "Password")]
    passWord: Option<String>,


    /// print supported protocol and service
    #[clap(long = "unauth", help = "check Unauthorized", action)]
    checkUnauth: bool,

}