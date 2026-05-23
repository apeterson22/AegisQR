use std::fs;

use aegisqr_core::{
    export_qr_packets, import_qr_packets, pack_to_file, unpack_capsule, PackOptions,
};

#[test]
fn scenario_roundtrip_file_and_qr_reconstruct() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("hello.txt");
    fs::write(&source, b"hello").unwrap();

    let capsule = dir.path().join("hello.aqr");
    pack_to_file(&source, &capsule, "pw", PackOptions::default()).unwrap();

    let out = dir.path().join("out");
    unpack_capsule(&capsule, &out, "pw").unwrap();
    assert_eq!(
        fs::read(&source).unwrap(),
        fs::read(out.join("hello.txt")).unwrap()
    );

    let qr = dir.path().join("qr");
    export_qr_packets(&capsule, &qr, 32, false).unwrap();
    let rebuilt = dir.path().join("rebuilt.aqr");
    import_qr_packets(&qr, &rebuilt).unwrap();
    assert_eq!(fs::read(&capsule).unwrap(), fs::read(rebuilt).unwrap());
}
