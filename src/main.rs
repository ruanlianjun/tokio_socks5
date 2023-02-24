use std::error::Error;
use std::io::{Cursor, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use chrono::Local;
use env_logger::Builder;
use log::{error, info, warn};
use log::LevelFilter::Info;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_log();

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    loop {
        let (mut socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            let mut buf = vec![0; 1024];

            let n = match socket.read(&mut buf).await {
                Ok(n) if n == 0 => {
                    warn!("read eof");
                    return;
                }
                Ok(n) => {
                    n
                }
                Err(e) => {
                    error!("read data have error:{}",e);
                    return;
                }
            };

            //VER(1)	NMETHODS(1)	METHODS(1)
            let tmp = &buf[..n];
            info!("read data:{:#?}",&tmp);

            //1.选择验证账号密码
            socket.write_all(&[0x05, 0x02]).await.unwrap();

            //2.验证账号密码
            let mut buf = vec![0; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let tmp = &buf[..n];
            info!("客户端发送的认证信息:{:#?}",tmp);
            let ulen = (tmp[1] as usize) + 1;
            let uname = &tmp[2..=ulen];
            info!("客户端发送的认证 uname:{:?}",String::from_utf8(uname.to_vec()));

            let plen = 1 + ulen;
            let password = &tmp[plen + 1..n];
            info!("客户端发送的认证 raw:{:?} password:{:?}",password,String::from_utf8(password.to_vec()));


            //3.验证通过告诉客户端
            socket.write_all(&[0x01, 0x00]).await.unwrap();

            //4.解析客户端发送过来的数据
            // VER	CMD	RSV	ATYP	DST.ADDR	DST.PORT
            // 1	1	0x00	1	Variable	2
            let mut buf = vec![0; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            info!("客户端请求信息:{:#?}",&buf[..n]);
            let port = Cursor::new(&buf[(n - 2)..n]).read_u16().await.unwrap();

            info!("ip请求类型是:{} port:{}",&buf[3],port);
            let addr = match buf[3] {
                0x01 => {
                    SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7])),
                        port,
                    )
                }
                0x02 => {
                    let domain = format!("{:?}:{:?}", String::from_utf8_lossy(&buf[5..n - 4]), port);
                    let mut addrs = domain.to_socket_addrs().unwrap();
                    addrs.next().unwrap()
                }
                0x03 | 0x04 => {
                    info!("ip:{:?} {:?} {:?} {:?} {:?}",&buf[4..6],&buf[6..8],&buf[8..10],&buf[10..12],&buf[12..14]);

                    SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::new(
                            Cursor::new(&buf[4..6]).read_u16().await.unwrap(),
                            Cursor::new(&buf[6..8]).read_u16().await.unwrap(),
                            Cursor::new(&buf[8..10]).read_u16().await.unwrap(),
                            Cursor::new(&buf[10..12]).read_u16().await.unwrap(),
                            Cursor::new(&buf[12..14]).read_u16().await.unwrap(),
                            Cursor::new(&buf[14..16]).read_u16().await.unwrap(),
                            Cursor::new(&buf[16..18]).read_u16().await.unwrap(),
                            Cursor::new(&buf[18..20]).read_u16().await.unwrap(),
                        )),
                        port)
                }
                _ => {
                    warn!("请求代码方式错误：{}",buf[3]);
                    return;
                }
            };

            // 响应用户请求
            socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            info!("connection：addr:{}",addr);

            let mut target = TcpStream::connect(addr).await.unwrap();

            // let mut remote = TcpStream::connect("127.0.0.1:7890").await.unwrap();


            let (mut sr, mut sw) = socket.split();
            let (mut tr, mut tw) = target.split();


            let client_to_server = async {
                copy(&mut sr, &mut tw).await?;
                tw.shutdown().await
            };

            let server_to_client = async {
                copy(&mut tr, &mut sw).await?;
                sw.shutdown().await
            };

            tokio::try_join!(client_to_server,server_to_client).unwrap();
        });
    }
}


fn init_log() {
    Builder::new().format(|buf, record| {
        writeln!(buf,
                 "{} [{}] - {}",
                 Local::now().format("%Y-%m-%d %H:%M:%S"),
                 record.level(),
                 record.args()
        )
    }).filter(None, Info).init();
}