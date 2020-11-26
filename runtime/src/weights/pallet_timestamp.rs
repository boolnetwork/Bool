#![allow(unused_parens)]

use frame_support::weights::{Weight, constants::RocksDbWeight as DbWeight};

pub struct WeightInfo;
impl pallet_timestamp::WeightInfo for WeightInfo {
	// WARNING! Some components were not used: ["t"]
	fn set() -> Weight {
		(9133000 as Weight)
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(1 as Weight))
	}
	// WARNING! Some components were not used: ["t"]
	fn on_finalize() -> Weight {
		(5915000 as Weight)
	}
}
