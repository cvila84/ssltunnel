use std::env;
use std::process::exit;

fn usage() {
    println!("Usage: SSLTunnel <inputStream> <remoteHost>:<remotePort> -p <proxyHost>:<proxyPort> -l <fileName>");
    println!("<inputStream> is either - for stdin or tcp:<listenPort> for TCP");
    println!("<remoteHost>:<remotePort> is the remote host to connect to");
    println!("-p <proxyHost>:<proxyPort> creates the tunnel through a HTTP proxy, direct SSL otherwise");
    println!("-l <fileName> writes log in a file, no log written otherwise");
    println!("-r retry in case of connection failure");
}

fn run() -> i32 {
    let mut i = 1;
    let mut stdin = false;
    let mut valid = true;
    let mut proxy = false;
    let mut proxy_host: String;
    let mut proxy_port: i32;
    let args: Vec<String> = env::args().collect();
    let l = args.len() - 1;
    if l == 0 {
        usage();
        return 1;
    }
    let mut it = args.iter();
    loop {
        let arg = match it.next() {
            Some(item) => item,
            None => break
        };
        if arg.starts_with("-") {
            if l == 1 {
                stdin = true;
                i = i+1;
            } else {
                valid = false;
                break;
            }
        } else {
            if arg[1] == 'p' {
                let proxy_addr = match it.next() {
                    Some(item) => item,
                    None => break
                };
                if let Some(j) = proxy_addr.find(":") {
                    if j < 1 || j == proxy_addr.len() - 1 {
                        valid = false;
                        break;
                    }
                }
                let proxy_addr_parts = proxy_addr.split(":").collect();
                proxy_host = proxy_addr_parts[0];
                proxy_port = proxy_addr_parts[1].parse::<i32>().unwrap_or(-1);
                proxy = true;
            }
        }
    }
    return 0;
}

fn main() {
    let status = run();
    exit(status)
}
