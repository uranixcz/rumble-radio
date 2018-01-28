extern crate rumble_radio;
extern crate protobuf;

mod mumble;

use rumble_radio::*;

fn main() {
    let address = "vm1336.cust.netio.cz";
    let port: u16 = 64738;
    let username = "RumbleRadio";
    let password = "vopice";
    let mut buffer: [u8; 1048576] = [0; 1048576];
    let ping = mumble::Ping::new();

    //establish_connection(address, port, username, password, &mut buffer);
    let mut stream = establish_connection(address, port, username, password, &mut buffer);

    /*loop {

        receive_message(&mut stream, &mut buffer);
        //receive_message(&mut stream, &mut buffer);
        thread::sleep(time);
        send_message(&mut stream, PING, &ping);
    }*/

    let mut cnt: u32 = 0;
    loop {
        if DEBUG {eprintln!("Waiting for message {}/13 until ping", cnt);}
        //if receive_message(&mut stream, &mut buffer) != UDPTUNEL {thread::sleep(time);}
        receive_message(&mut stream, &mut buffer);

        if cnt == 13 { // 14 cycles * 2s read timeout < 30s server timeout
            if DEBUG { eprintln!("Sending ping..."); }
            send_message(&mut stream, PING, &ping);
            cnt = 0;
        } else { cnt += 1; }
    }

    /*let mut v = Mumble::Version::new();
    v.set_version(1);
    v.set_os(String::from("OS Unknown"));
    v.set_os_version(String::from("0.0.1"));
    v.set_release(String::from("Rumble radio"));
    let mut v = rumble_radio::get_version();

    let mut ssl_builder = SslConnectorBuilder::new(SslMethod::tls())
        .unwrap();
    ssl_builder.set_verify(SSL_VERIFY_NONE);
    let connector = ssl_builder.build();

    let stream = TcpStream::connect("vm1336.cust.netio.cz:64738").unwrap();
    let mut stream = connector
        .connect("vm1336.cust.netio.cz", stream)
        .expect("unable to connect");

    //let mut array: [u8; 2] = 56::u32.into();
    //[u8] = 56.into();
    stream.write(&[0,0]).unwrap();
    stream.write(&transform_u32_to_array_of_u8(v.compute_size())).unwrap();
    {
        let mut out = CodedOutputStream::new(&mut stream);
        let bz = v.write_to(&mut out).unwrap();
        out.flush().unwrap();
    }

    //stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    stream.flush().unwrap();
    let mut res = vec![];
    eprintln!("{}", stream.read_to_end(&mut res).unwrap());
    eprintln!("{}", String::from_utf8_lossy(&res));*/



    /*let mut f = File::open("tst.txt").unwrap();
    /*let mut f = File::create("tst.txt").unwrap();
    {
        let mut o = CodedOutputStream::new(&mut f);

        let mut v = Mumble::Version::new();
        v.set_version(1);
        v.set_release(String::from("Rumble radio"));
        v.write_to(&mut o).expect("nefunguje");
        o.flush().expect("neslo flushnout");
    }
*/
    //let mut buffer = vec![0; 10];
    let mut str = String::new();
    f.read_to_string(&mut str);
    let mut str = str.as_bytes();
    let mut i = CodedInputStream::new(&mut str);
    let mut w = Mumble::Version::new();
    match w.merge_from(&mut i) {
        Ok(s) => eprintln!("{:?}", s),
        Err(e) => eprintln!("{}", e),
    }
    eprintln!("{:?}", w);*/

}