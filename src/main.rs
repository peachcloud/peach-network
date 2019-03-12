use jsonrpc_http_server::jsonrpc_core::types::error::Error;
use jsonrpc_http_server::jsonrpc_core::*;
use jsonrpc_http_server::*;

// define the Iface struct for interface parameter
#[derive(Debug, Deserialize)]
pub struct Iface {
    iface: String,
}

fn main() {
    let mut io = IoHandler::default();

    io.add_method("get_ip", move |params: Params| {
        // parse parameters and match on result
        let i: Result<Iface> = params.parse();
        match i {
            // if result contains parameters, unwrap and validate
            Ok(_) => {
                let i: Iface = i.unwrap();
                Ok(Value::String("success".into()))
            }
            Err(e) => println!("{:?}", e),
        }
    });

    io.add_method("get_ssid", move |_| {
        Ok(Value::String("success".into()))
    });

    let server = ServerBuilder::new(io)
        .cors(DomainsValidation::AllowOnly(vec![
            AccessControlAllowOrigin::Null,
        ]))
        .start_http(&"127.0.0.1:3030".parse().unwrap())
        .expect("Unable to start RPC server");

    server.wait();
}
