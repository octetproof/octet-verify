// Generates Rust protobuf types from the vendored, public-safe schema under
// `proto/octet/**`. The generated modules land in $OUT_DIR and are re-exported
// from `src/lib.rs` under the `navigate` and `attest` namespaces.
//
// The vendored proto tree is a curated, public-safe subset of the SDK's wire
// schema: the full LocationProof message, plus only the verdict enum and proof
// envelope a verifier needs. The SDK's internal detection types are not
// vendored.

use std::path::PathBuf;

fn main() {
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("proto");

    let files = [
        "octet/proof/proof.proto",
        "octet/attest/continuous.proto",
    ];

    let protos: Vec<PathBuf> = files.iter().map(|f| proto_root.join(f)).collect();

    // Re-run when any .proto changes.
    for p in &protos {
        println!("cargo:rerun-if-changed={}", p.display());
    }

    // Use a vendored protoc so the build is fully self-contained: no system
    // `protobuf-compiler` is needed by CI or by anyone building/auditing the
    // crate. prost-build invokes whatever the PROTOC env var points at.
    let protoc = protoc_bin_vendored::protoc_bin_path()
        .expect("vendored protoc binary unavailable for this target");
    std::env::set_var("PROTOC", protoc);

    let mut cfg = prost_build::Config::new();
    cfg.compile_protos(&protos, &[proto_root])
        .expect("failed to compile vendored octet protos");
}
