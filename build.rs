fn main() {
    tonic_build::compile_protos("proto/dns_guard.proto")
        .unwrap_or_else(|e| panic!("failed to compile proto: {e}"));
}
