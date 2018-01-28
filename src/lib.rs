extern crate protobuf;
extern crate openssl;
extern crate varinteger;
extern crate opus;
use openssl::ssl::SSL_VERIFY_NONE;

//use std::io::prelude::*;
use std::net::TcpStream;
use openssl::ssl::{SslMethod, SslConnectorBuilder, SslStream};
use std::io::{Read, Write};
use protobuf::*;
//use std::io::ErrorKind;
use std::slice;
use std::mem;

mod mumble;

//use Mumble::{Version, Authenticate, CryptSetup};
use mumble::*;

pub static DEBUG: bool = true;

const VERSION: u8 = 0;
pub const UDPTUNEL: u8 = 1;
const AUTHENTICATE: u8 = 2;
pub const PING: u8 = 3;
const REJECT: u8 = 4;
const SERVERSYNC: u8 = 5;
//const CHANNELREMOVE: u8 = 6;
const CHANNELSTATE: u8 = 7;
//const USERREMOVE: u8 = 8;
const USERSTATE: u8 = 9;
//const BANLIST: u8 = 10;
const TEXTMESSAGE: u8 = 11;
//const PERMISSIONDENIED: u8 = 12;
//const ACL: u8 = 13;
//const QUERYUSERS: u8 = 14;
const CRYPTSETUP: u8 = 15;
//const CONTEXTACTIONMODIFY: u8 = 16;
//const CONTEXTACTION: u8 = 17;
//const USERLIST: u8 = 18;
//const VOICETARGET: u8 = 19;
const PERMISSIONQUERY: u8 = 20;
const CODECVERSION: u8 = 21;
//const USERSTATS: u8 = 22;
//const REQUESTBLOB: u8 = 23;
const SERVERCONFIG: u8 = 24;
//const SUGGESTCONFIG: u8 = 25;*/

/*pub struct Config {
    version: Version,
    //authenticate: Authenticate,
}

impl Config {

    fn new() -> Config {

    }

}*/

fn get_version() -> Version {
    let mut v = mumble::Version::new();
    v.set_version(0x00010213);
    v.set_os(String::from("OS Unknown"));
    v.set_os_version(String::from("0.0.1"));
    v.set_release(String::from("Rumble radio"));
    v
}

fn get_authenticate(username: &str, password: &str) -> Authenticate {
    let mut a = Authenticate::new();
    a.set_username(String::from(username));
    a.set_password(String::from(password));
    a.set_opus(true);
    //a.clear_celt_versions();
    a
}

pub fn send_message(stream: &mut SslStream<TcpStream>, msg_type: u8, msg: &Message) {
    stream.ssl_write(&[0, msg_type]).unwrap();
    stream.ssl_write(&transform_u32_to_array_of_u8(msg.compute_size())).unwrap();
    {
        let mut cos = CodedOutputStream::new(stream);
        msg.write_to(&mut cos).unwrap();
        cos.flush().unwrap();
    }
}

pub fn receive_message(stream: &mut SslStream<TcpStream>, buffer: &mut [u8]) -> u8 {
    let mut type_buf: [u8; 6] = [0; 6];
    //let mut msg_buf: [u8; 1048576] = [0; 1048576];
    //let mut bufread = BufReader::new(stream);
    //if bufread.is_empty() {return 255;}
    //if stream.read(&mut type_buf).unwrap() == 0 {return 255;}
    match stream.read(&mut type_buf) { //buffer[..6]
        Err(_) => {if DEBUG {eprintln!("read err (timeout etc)")};
            //send_message(&mut stream, PING, &Ping::new());
            return 255;},
        Ok(0) => {eprintln!("Ok0 error"); std::thread::sleep_ms(10000);},
        Ok(_) => {}
    }
    let msg_type: u8 = type_buf[1];
    let mut length_b: [u8; 4] = [0,0,0,0];
    length_b.copy_from_slice(&type_buf[2..6]);

    let length = transform_array_of_u8_to_usize(length_b);
    if DEBUG {eprintln!("new data, length: {}", length);}
    stream.read_exact(&mut buffer[..length]).unwrap();

    let mut cis = CodedInputStream::from_bytes(& buffer[..length]);
    if DEBUG {eprintln!("message code: {}", msg_type);}
    match msg_type {
        VERSION => {
            let mut srv_msg = Version::new();
            srv_msg.merge_from(&mut cis).unwrap();
            if DEBUG {eprintln!("Server version {:x}", srv_msg.get_version());}
        },
        UDPTUNEL => {
            let packet: &[u8] = &buffer[..length];
            if packet[0] >= 128 {
                let mut size = 0u64;
                if DEBUG { eprintln!("{:?}", &packet);}
                let mut offset = varinteger::decode_with_offset(&packet, 1, &mut size);
                //if DEBUG { eprintln!("packet length {}", &packet.len());}
                if DEBUG { eprintln!("offset1 {}", offset);}
                offset += varinteger::decode_with_offset(&packet, offset, &mut size);
                if DEBUG { eprintln!("offset2 {}", offset);}
                let mut terminator = false;
                while offset < packet.len() && !terminator {
                    offset += varinteger::decode_with_offset(&packet, offset, &mut size);
                    if (size & 0x2000) ==0 { terminator = true;}
                    size &= 0x1fff;
                    /*if DEBUG { eprintln!("offset3 {}", offset);}
                if DEBUG { eprintln!("payload length {}", tmp);}*/
                    //if DEBUG { eprintln!("data: {}", String::from_utf8_lossy(&packet[offset..]));}
                    if size > 0 {
                        /*let mut pcm = [0i16; 9000];
                        let mut opus = opus::Decoder::new(48000, opus::Channels::Stereo).unwrap();
                        let bla = opus.decode(&packet[offset..], &mut pcm[..], false).unwrap();

                        let slice_u8: &[u8] = unsafe {
                            slice::from_raw_parts(
                                pcm[..bla].as_ptr() as *const u8,
                                pcm[..bla].len() * mem::size_of::<i16>(),
                            )
                        };
                        let mut out = std::io::stdout();
                        out.write(&slice_u8);
                        out.flush().unwrap();*/
                        let mut out = std::io::stdout();
                        out.write(&packet[offset..]).unwrap();
                        out.flush().unwrap();
                    }
                }
            }
        },
        CRYPTSETUP => {
            let mut srv_msg = CryptSetup::new();
            srv_msg.merge_from(&mut cis).unwrap();
            if DEBUG {eprintln!("crypt ok");}
            //std::process::exit(0x0100);
        },
        REJECT => {
            let mut srv_msg = Reject::new();
            srv_msg.merge_from(&mut cis).unwrap();
            eprintln!("{}", srv_msg.get_reason());
            std::process::exit(0x0001);
        },
        CHANNELSTATE => {
            let mut srv_msg = ChannelState::new();
            srv_msg.merge_from(&mut cis).unwrap();
            if DEBUG {eprintln!("channel name: {}", srv_msg.get_name());}
        },
        USERSTATE => {
            let mut srv_msg = UserState::new();
            srv_msg.merge_from(&mut cis).unwrap();
            if DEBUG {eprintln!("user name: {}", srv_msg.get_name());}
        },
        SERVERSYNC => {
            let mut srv_msg = ServerSync::new();
            srv_msg.merge_from(&mut cis).unwrap();
            if DEBUG {
                eprintln!("max bandwidth: {}", srv_msg.get_max_bandwidth());
                eprintln!("welcome message: {}", srv_msg.get_welcome_text());
            }
        },
        CODECVERSION => {
            let mut srv_msg = CodecVersion::new();
            srv_msg.merge_from(&mut cis).unwrap();
            if DEBUG {
                eprintln!("celt alpha int: {}", srv_msg.get_alpha());
                eprintln!("celt beta int: {}", srv_msg.get_beta());
                eprintln!("opus enabled: {}", srv_msg.get_opus());
                //eprintln!("codec type: {}", srv_msg.get_type_id());
            }
        },
        TEXTMESSAGE => {
            let mut srv_msg = TextMessage::new();
            srv_msg.merge_from(&mut cis).unwrap();
            eprintln!("text from {}:{}", srv_msg.get_actor(), srv_msg.get_message());
        },
        PERMISSIONQUERY => {
            let mut srv_msg = PermissionQuery::new();
            srv_msg.merge_from(&mut cis).unwrap();
            eprintln!("channel {} permissions: {:x}", srv_msg.get_channel_id(), srv_msg.get_permissions());
        },
        SERVERCONFIG => {
            let mut srv_msg = ServerConfig::new();
            srv_msg.merge_from(&mut cis).unwrap();
            if DEBUG {
                eprintln!("max bandwidth: {}", srv_msg.get_max_bandwidth());
                eprintln!("welcome message: {}", srv_msg.get_welcome_text());
            }
        },
        PING => {
            let mut srv = Ping::new();
            srv.merge_from(&mut cis).unwrap();
            /*if DEBUG {eprintln!("{} good: {}; late: {}; ping avg: {}", srv.get_timestamp(),
                               srv.get_good(), srv.get_late(), srv.get_tcp_ping_avg()); }*/
        },
        _ => {}
    }

    msg_type
}

pub fn establish_connection(address: &str, port: u16, username: &str, password: &str,
                            buffer: &mut [u8]) -> SslStream<TcpStream> {
    let mut ssl_builder = SslConnectorBuilder::new(SslMethod::tls())
        .unwrap();
    ssl_builder.set_verify(SSL_VERIFY_NONE);
    let connector = ssl_builder.build();

    let stream = TcpStream::connect(format!("{}:{}", address, port)).unwrap();
    stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set_read_timeout call failed");
    let mut stream = connector
        .connect(address, stream)
        .expect("unable to connect");

    let version = get_version();
    send_message(&mut stream, VERSION, &version);

    /*stream.write(&[0,VERSION]).unwrap();
    stream.write(&transform_u32_to_array_of_u8(version.compute_size())).unwrap();
    {
        let mut out = CodedOutputStream::new(&mut stream);
        version.write_to(&mut out).unwrap();
        out.flush().unwrap();
    }*/
    //stream.flush().unwrap();

    receive_message(&mut stream, buffer);
    /*stream.read(&mut buffer[..6]).unwrap();

    let mut length_b: [u8; 4] = [0,0,0,0];
    length_b.copy_from_slice(&buffer[2..6]);

    let mut length = transform_array_of_u8_to_usize(length_b);
    stream.read(&mut buffer[..length]).unwrap();
    let mut srv_version = Version::new();

    let mut cis = CodedInputStream::from_bytes(&mut buffer[..length]);
    srv_version.merge_from(&mut cis).unwrap();
    eprintln!("{:?}", srv_version.get_version());*/

    /*let mut buffer: [u8; 1048576] = [0; 1048576];
    stream.read(&mut buffer[..]);
    for (i,u) in buffer.iter().enumerate() {
        if i < 500 {eprintln!("{}", u);}
        else { break }
    }*/

    /*let mut res = vec![];
    stream.read_to_end(&mut res).unwrap();
    for i in res {
        eprintln!("{}", i);
    }*/
    //eprintln!("{}", String::from_utf8_lossy(&res));
    //eprintln!("{}", String::from_utf8_lossy(&res));
    //let mut cis = CodedInputStream::from_bytes(&mut res[5..]);
    //eprintln!("{}", &cis.read_string().unwrap());
    //eprintln!("{}", String::from_utf8_lossy(&cis.read_string()));

    let authenticate = get_authenticate(&username, &password);
    send_message(&mut stream, AUTHENTICATE, &authenticate);

    while receive_message(&mut stream, buffer) != SERVERSYNC {}

    send_message(&mut stream, PING, &Ping::new());
    receive_message(&mut stream, buffer);

    stream
}

fn transform_u32_to_array_of_u8(x:u32) -> [u8;4] {
    let b1 : u8 = ((x >> 24) & 0xff) as u8;
    let b2 : u8 = ((x >> 16) & 0xff) as u8;
    let b3 : u8 = ((x >> 8) & 0xff) as u8;
    let b4 : u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4]
}

/*fn transform_array_of_u8_to_u32(x:[u8;4]) -> u32 {
    let mut a:u32 = u32::from(x[0]);
    a = a << 8;
    a += u32::from(x[1]);
    a = a << 8;
    a += u32::from(x[2]);
    a = a << 8;
    a + u32::from(x[3])
}*/

fn transform_array_of_u8_to_usize(x:[u8;4]) -> usize {
    let mut a:usize = usize::from(x[0]);
    a = a << 8;
    a += usize::from(x[1]);
    a = a << 8;
    a += usize::from(x[2]);
    a = a << 8;
    a + usize::from(x[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transform() {
        assert_eq!(transform_u32_to_array_of_u8(0x03030303), [3,3,3,3]);
        assert_eq!(transform_array_of_u8_to_usize([3,3,3,3]), 0x03030303);
        assert_eq!(transform_u32_to_array_of_u8(268441600), [16,0,24,0]);
        assert_eq!(transform_array_of_u8_to_usize([16,0,24,0]), 268441600)
    }
}