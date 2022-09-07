use ink_storage::traits::ManualKey;

#[ink::storage_item]
struct Contract<KEY: ::ink_storage::traits::StorageKey = ManualKey<123>> {
    a: u16,
    b: u16,
    c: u16,
}

fn main() {
    assert_eq!(<Contract as ::ink_storage::traits::StorageKey>::KEY, 123);
}
