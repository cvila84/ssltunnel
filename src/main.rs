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
    let mut stdin = false;
    let mut valid = true;
    let mut proxy = false;
    let mut proxy_host: &str = "";
    let mut proxy_port: i32;
    let mut log_file: bool = false;
    let mut log_file_name: &str = "";
    let mut retry = false;
    let mut tcp_listen_port : i32;
    let mut remote_host: &str = "";
    let mut remote_port: i32;
    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    if args.len() <= 1 {
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
            if arg.len() == 1 {
                if i == 1 {
                    stdin = true;
                    i = i + 1;
                } else {
                    valid = false;
                    break;
                }
            } else {
                let f = (&arg[1..2]).as_bytes().first().unwrap();
                if *f == b'p' {
                    let proxy_addr = match it.next() {
                        Some(item) => item,
                        None => break
                    };
                    if let Some(j) = proxy_addr.find(":") {
                        if j < 1 || j == proxy_addr.len() - 1 {
                            valid = false;
                            break;
                        }
                        let mut proxy_port_str: &str = "";
                        (proxy_host, proxy_port_str) = proxy_addr.split_at(j);
                        proxy_port = (&proxy_port_str[1..]).parse::<i32>().unwrap_or(-1);
                        if proxy_port < 0 {
                            valid = false;
                            break;
                        }
                        proxy = true;
                    }
                } else if *f == b'l' {
                    log_file_name = match it.next() {
                        Some(item) => item,
                        None => {
                            valid = false;
                            break;
                        }
                    };
                    log_file = true;
                } else if *f == b'r' {
                    retry = true;
                } else {
                    valid = false;
                }
            }
        } else {
            if i == 1 && arg.starts_with("tcp:") {
                tcp_listen_port = (&arg[4..]).parse::<i32>().unwrap_or(-1);
                i = i + 1;
            } else if i == 2 {
                if let Some(j) = arg.find(":") {
                    if j < 1 || j == arg.len() - 1 {
                        valid = false;
                        break;
                    }
                    let mut remote_port_str: &str = "";
                    (remote_host, remote_port_str) = arg.split_at(j);
                    remote_port = (&remote_port_str[1..]).parse::<i32>().unwrap_or(-1);
                    if remote_port < 0 {
                        valid = false;
                        break;
                    }
                    i = i + 1;
                } else {
                    valid = false;
                    break;
                }
            }
        }
    }
    if i < 3 {
        valid = false;
    }
    if !valid {
        usage();
        return 1;
    }
    return 0;
}

fn main() {
    let status = run();
    exit(status)
}
