fn main() {
    // don't link with stdlib
    println!("cargo:rustc-link-arg-bin=echidna=-nostartfiles");
}