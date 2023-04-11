use bitcoin::hashes::Hash;
use bitcoin::network::constants::Network;
use bitcoin::opcodes::all::*;
use bitcoin::secp256k1;
use bitcoin::Address;

use bitcoin::taproot;
use secp256k1::rand;

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        println!("Invalid number of args");
        return;
    }

    let prefix = args[1].to_lowercase();
    if prefix.len() <= 4 {
        println!("Prefix is too short");
        return;
    }
    if prefix.get(0..4) != Some("bc1p") {
        println!("Invalid prefix, must begin with bc1p");
        return;
    }

    // 0 [1] 23456789 a [b] cdefgh [i] jklmn [o] pqrstuvwxyz
    const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let prefix_split: Vec<&str> = prefix.split("1").collect();
    for pc in prefix_split[1].chars() {
        if !CHARSET.contains(pc) {
            println!("Invalid character in prefix");
            return;
        }
    }

    //let mut merkle_root: Option<taproot::TapNodeHash> = None;

    let secp = secp256k1::Secp256k1::new();

    let (collection_secret, _collection_public) = secp.generate_keypair(&mut rand::thread_rng());
    let (collection_xopk, _) = collection_secret.x_only_public_key(&secp);

    let (artist_secret, _artist_public) = secp.generate_keypair(&mut rand::thread_rng());
    let (artist_xopk, _) = artist_secret.x_only_public_key(&secp);

    let inscribor: Vec<_> = vec![collection_xopk, artist_xopk];

    if inscribor.len() == 0 {
        panic!("Need at least 1 inscribor");
    }

    let genesis = match inscribor.len() {
        0 => panic!("Need at least 1 inscribor"),
        1 => {
            let genesis = bitcoin::script::Builder::new();
            genesis
                .push_x_only_key(&inscribor[0])
                .push_opcode(OP_CHECKSIGVERIFY)
                .as_script()
                .to_owned()
        }
        _ => {
            let mut genesis = bitcoin::script::Builder::new()
                .push_x_only_key(&inscribor[0])
                .push_opcode(OP_CHECKSIG);

            for x_only_key in inscribor.iter().skip(1) {
                genesis = genesis
                    .push_x_only_key(x_only_key)
                    .push_opcode(OP_CHECKSIGADD);
            }
            genesis = genesis
                .push_int(inscribor.len() as i64)
                .push_opcode(OP_EQUALVERIFY);

            genesis.as_script().to_owned()
        }
    };

    // todo append the inscription
    let mut nonce: u64 = 0;
    let counter = [0; 32];
    let start = std::time::Instant::now();

    loop {
        nonce += 1;

        let foo: [u8; 8] = nonce.to_le_bytes();
        let mut counter = counter.clone();
        for i in 0..foo.len() {
            counter[i] = foo[i];
        }
        let counter = taproot::TapNodeHash::from_slice(&counter).unwrap();
        let spend_info = taproot::TaprootBuilder::new()
            .add_hidden_node(1, counter)
            .unwrap()
            .add_leaf(1, genesis.clone())
            .unwrap()
            .finalize(&secp, collection_xopk)
            .unwrap();

        let addr = Address::p2tr(
            &secp,
            collection_xopk,
            spend_info.merkle_root(),
            Network::Bitcoin,
        );

        // potential speedup: convert prefix to desired bytes instead of calculating address
        if addr.to_string().get(0..prefix.len()) == Some(&prefix) {
            println!(
                "collection_secret: {:?}",
                collection_secret.display_secret()
            );
            println!("collection_xopk: {:?}", collection_xopk);
            //dbg!(spend_info);
            let duration = std::time::Instant::now() - start;
            println!(
                "Ops / Nonce:  {:.0} / {}",
                nonce as f64 / duration.as_secs_f64(),
                nonce
            );
            println!("CommitAddress: {}", addr);
            break;
        }
    }
}

// 0la3s
