#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::weights::{Weight, constants::RocksDbWeight as DbWeight};

pub struct WeightInfo;
impl pallet_im_online::WeightInfo for WeightInfo {
	fn validate_unsigned_and_then_heartbeat(k: u32, e: u32, ) -> Weight {
		(139830000 as Weight)
			.saturating_add((211000 as Weight).saturating_mul(k as Weight))
			.saturating_add((654000 as Weight).saturating_mul(e as Weight))
			.saturating_add(DbWeight::get().reads(4 as Weight))
			.saturating_add(DbWeight::get().writes(1 as Weight))
	}
}
