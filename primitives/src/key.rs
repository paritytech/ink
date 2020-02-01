// Copyright 2018-2019 Parity Technologies (UK) Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::byte_utils;
use scale::{
    Decode,
    Encode,
};

/// Typeless generic key into contract storage.
///
/// Can be compared to a raw pointer featuring pointer arithmetic.
///
/// # Note
///
/// This is the most low-level method to access contract storage.
///
/// # Unsafe
///
/// - Does not restrict ownership.
/// - Can read and write to any storage location.
/// - Does not synchronize between main memory and contract storage.
/// - Violates Rust's mutability and immutability guarantees.
///
/// Prefer using types found in `collections` or `Synced` type.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct Key(pub [u8; 32]);

#[cfg(feature = "std")]
impl type_metadata::HasTypeId for Key {
    fn type_id() -> type_metadata::TypeId {
        type_metadata::TypeIdCustom::new(
            "Key",
            type_metadata::Namespace::from_module_path("ink_primitives")
                .expect("non-empty Rust identifier namespaces cannot fail"),
            Vec::new(),
        )
        .into()
    }
}

#[cfg(feature = "std")]
impl type_metadata::HasTypeDef for Key {
    fn type_def() -> type_metadata::TypeDef {
        use ink_prelude::vec;
        type_metadata::TypeDefTupleStruct::new(vec![type_metadata::UnnamedField::of::<
            [u8; 32],
        >()])
        .into()
    }
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Key(")?;
        <Self as core::fmt::Display>::fmt(self, f)?;
        write!(f, ")")?;
        Ok(())
    }
}

impl core::fmt::Display for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "0x")?;
        if f.alternate() {
            let bytes = self.as_bytes();
            write!(
                f,
                "{:02X}{:02X}_{:02X}{:02X}_……_{:02X}{:02X}_{:02X}{:02X}",
                bytes[0],
                bytes[1],
                bytes[2],
                bytes[3],
                bytes[28],
                bytes[29],
                bytes[30],
                bytes[31],
            )?;
        } else {
            for (n, byte) in self.as_bytes().iter().enumerate() {
                write!(f, "{:02X}", byte)?;
                if n % 4 == 0 && n != 32 {
                    write!(f, "_")?;
                }
            }
        }
        Ok(())
    }
}

impl Key {
    /// Returns the byte slice of this key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the mutable byte slice of this key.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl core::ops::Sub for Key {
    type Output = KeyDiff;

    fn sub(self, rhs: Self) -> KeyDiff {
        let mut lhs = self;
        let mut rhs = rhs;
        byte_utils::negate_bytes(rhs.as_bytes_mut());
        byte_utils::bytes_add_bytes(lhs.as_bytes_mut(), rhs.as_bytes());
        KeyDiff(lhs.0)
    }
}

/// The difference between two keys.
///
/// This is the result of substracting one key from another.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyDiff([u8; 32]);

macro_rules! impl_try_to_prim {
	(
		$( #[$attr:meta] )*
		$name:ident, $prim:ty, $conv:ident
	) => {
		impl KeyDiff {
			$( #[$attr] )*
			pub fn $name(&self) -> Option<$prim> {
				const KEY_BYTES: usize = 32;
				const PRIM_BYTES: usize = core::mem::size_of::<$prim>();
				if self.as_bytes().iter().take(KEY_BYTES - PRIM_BYTES).any(|&byte| byte != 0x0) {
					return None
				}
				let value = <$prim>::from_be_bytes(
					*byte_utils::$conv(&self.as_bytes()[(KEY_BYTES - PRIM_BYTES)..KEY_BYTES])
						.unwrap()
				);
				Some(value)
			}
		}
	};
}

impl_try_to_prim!(
    /// Tries to convert the key difference to a `u32` if possible.
    ///
    /// Returns `None` if the resulting value is out of bounds.
    try_to_u32,
    u32,
    slice4_as_array4
);
impl_try_to_prim!(
    /// Tries to convert the key difference to a `u64` if possible.
    ///
    /// Returns `None` if the resulting value is out of bounds.
    try_to_u64,
    u64,
    slice8_as_array8
);
impl_try_to_prim!(
    /// Tries to convert the key difference to a `u128` if possible.
    ///
    /// Returns `None` if the resulting value is out of bounds.
    try_to_u128,
    u128,
    slice16_as_array16
);

impl KeyDiff {
    /// Returns the byte slice of this key difference.
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

macro_rules! impl_add_sub_for_key {
    ( $prim:ty ) => {
        impl core::ops::Add<$prim> for Key {
            type Output = Self;

            fn add(self, rhs: $prim) -> Self::Output {
                let mut result = self;
                result += rhs;
                result
            }
        }

        impl core::ops::AddAssign<$prim> for Key {
            fn add_assign(&mut self, rhs: $prim) {
                byte_utils::bytes_add_bytes(self.as_bytes_mut(), &(rhs.to_be_bytes()));
            }
        }

        impl core::ops::Sub<$prim> for Key {
            type Output = Self;

            fn sub(self, rhs: $prim) -> Self::Output {
                let mut result = self;
                result -= rhs;
                result
            }
        }

        impl core::ops::SubAssign<$prim> for Key {
            fn sub_assign(&mut self, rhs: $prim) {
                byte_utils::bytes_sub_bytes(self.as_bytes_mut(), &rhs.to_be_bytes());
            }
        }
    };
}

impl_add_sub_for_key!(u32);
impl_add_sub_for_key!(u64);
impl_add_sub_for_key!(u128);

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        env,
        env::{
            EnvError,
            Result,
        },
        test_utils::run_test,
    };

    #[test]
    fn store_load_clear() -> Result<()> {
        env::test::run_test::<env::DefaultEnvTypes, _>(|_| {
            let key = Key([0x42; 32]);
            assert_eq!(
                env::get_contract_storage::<()>(key),
                Err(EnvError::MissingContractStorageEntry),
            );
            env::set_contract_storage(key, &[0x05_u8; 5]);
            assert_eq!(env::get_contract_storage::<[i8; 5]>(key), Ok([0x05; 5]),);
            env::clear_contract_storage(key);
            assert_eq!(
                env::get_contract_storage::<[u8; 5]>(key),
                Err(EnvError::MissingContractStorageEntry),
            );
            Ok(())
        })
    }

    #[test]
    fn key_add() -> Result<()> {
        env::test::run_test::<env::DefaultEnvTypes, _>(|_| {
            let key00 = Key([0x0; 32]);
            let key05 = key00 + 05_u32; // -> 5
            let key10 = key00 + 10_u32; // -> 10         | same as key55
            let key55 = key05 + 05_u32; // -> 5 + 5 = 10 | same as key10
            env::set_contract_storage(key55, &42);
            assert_eq!(env::get_contract_storage::<i32>(key10), Ok(42));
            env::set_contract_storage(key10, &1337);
            assert_eq!(env::get_contract_storage::<i32>(key55), Ok(1337));
            Ok(())
        })
    }

    #[test]
    fn key_add_sub() -> Result<()> {
        env::test::run_test::<env::DefaultEnvTypes, _>(|_| {
            let key0a = Key([0x0; 32]);
            let key1a = key0a + 1337_u32;
            let key2a = key0a + 42_u32;
            let key3a = key0a + 52_u32;
            let key2b = key3a - 10_u32;
            let key1b = key2b - 42_u32;
            let key0b = key1b + 2000_u32 - 663_u32; // same as key1a
            env::set_contract_storage(key0a, &1);
            env::set_contract_storage(key1a, &2);
            env::set_contract_storage(key2a, &3);
            assert_eq!(env::get_contract_storage::<i32>(key2b), Ok(3));
            assert_eq!(env::get_contract_storage::<i32>(key1b), Ok(1));
            assert_eq!(env::get_contract_storage::<i32>(key0b), Ok(2));
            Ok(())
        })
    }

    #[test]
    fn key_sub() {
        run_test(|| {
            assert_eq!(Key([0x42; 32]), Key([0x42; 32]));
            assert_eq!(Key([0x00; 32]) - 1_u32, Key([0xFF; 32]));
            assert_eq!(
                Key([0x01; 32]) - 1_u32,
                Key([
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00
                ])
            );
            {
                let key_u32_max_value = Key([
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                ]);
                assert_eq!(key_u32_max_value - u32::max_value(), Key([0x00; 32]));
            }
            {
                let key_a = Key([
                    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x10, 0x20, 0x30,
                    0x40, 0x50, 0x60, 0x70, 0x80, 0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5,
                    0x06, 0x17, 0x00, 0x22, 0x44, 0x66, 0x88, 0xAA, 0xCC, 0xEE,
                ]);
                let b: u32 = 0xFA09_51C3;
                let expected_b = Key([
                    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x10, 0x20, 0x30,
                    0x40, 0x50, 0x60, 0x70, 0x80, 0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5,
                    0x06, 0x17, 0x00, 0x22, 0x44, 0x65, 0x8E, 0xA1, 0x7B, 0x2B,
                ]);
                assert_eq!(key_a - b, expected_b);
                let c: u64 = 0xFBDC_BEEF_9999_1234;
                let expected_c = Key([
                    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x10, 0x20, 0x30,
                    0x40, 0x50, 0x60, 0x70, 0x80, 0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5,
                    0x06, 0x16, 0x04, 0x45, 0x85, 0x76, 0xEF, 0x11, 0xBA, 0xBA,
                ]);
                assert_eq!(key_a - c, expected_c);
            }
        })
    }

    #[test]
    fn as_bytes() {
        run_test(|| {
            let mut key = Key([0x42; 32]);
            assert_eq!(key.as_bytes(), &[0x42; 32]);
            assert_eq!(key.as_bytes_mut(), &mut [0x42; 32]);
        })
    }

    #[test]
    fn key_diff() {
        run_test(|| {
            let key1 = Key([0x0; 32]);
            let key2 = key1 + 0x42_u32;
            let key3 = key1 + u32::max_value() + 1_u32;
            let key4 = key1 + u64::max_value();
            assert_eq!(
                key2 - key1,
                KeyDiff([
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
                ])
            );
            assert_eq!((key2 - key1).try_to_u32(), Some(0x42));
            assert_eq!((key2 - key1).try_to_u64(), Some(0x42));
            assert_eq!(
                key3 - key1,
                KeyDiff([
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                ])
            );
            assert_eq!((key3 - key1).try_to_u32(), None);
            assert_eq!(
                (key3 - key1).try_to_u64(),
                Some(u32::max_value() as u64 + 1)
            );
            assert_eq!(
                key4 - key1,
                KeyDiff([
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                ])
            );
            assert_eq!((key4 - key1).try_to_u32(), None);
            assert_eq!((key4 - key1).try_to_u64(), Some(u64::max_value()));
            assert_eq!(
                key4 - key3,
                KeyDiff([
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
                ])
            );
            assert_eq!((key4 - key1).try_to_u32(), None);
            assert_eq!(
                (key4 - key3).try_to_u64(),
                Some(u64::max_value() - (u32::max_value() as u64 + 1))
            );
        })
    }
}
