use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::JsonBytes;
use ckb_mock_tx_types::ReprMockTransaction;
use ckb_types::H256;
use log::info;
use serde_json::{from_str, to_string_pretty};

pub fn build_ckb_tx(proof: &[u8], params: &[u8], vk: &[u8], binary_name: &str) {
    let mut tx: ReprMockTransaction =
        from_str(&String::from_utf8_lossy(include_bytes!("../../res/dummy_tx.json"))).expect("json");

    tx.tx.witnesses[0] = JsonBytes::from_vec(params.to_vec());
    tx.tx.witnesses[1] = JsonBytes::from_vec(vk.to_vec());
    tx.tx.witnesses[2] = JsonBytes::from_vec(proof.to_vec());

    let binary = std::fs::read(binary_name).expect("read");
    let hash = blake2b_256(&binary).to_vec();

    tx.mock_info.inputs[0].output.lock.code_hash = H256::from_slice(&hash).expect("H256");
    tx.mock_info.cell_deps[0].data = JsonBytes::from_vec(binary);

    let json = to_string_pretty(&tx).expect("json");
    std::fs::write("res/tx.json", &json).expect("write");

    info!("res/tx.json is generated for binary file: {}", binary_name);
}
