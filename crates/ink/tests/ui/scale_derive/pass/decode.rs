#[ink::scale_derive(decode)]
struct S;

fn is_decode<T: ::ink::scale::Decode>(_: T) {}

fn main() {
    is_decode(S);
}