#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::weights::{Weight, constants::RocksDbWeight as DbWeight};

pub struct WeightInfo;
impl pallet_scheduler::WeightInfo for WeightInfo {
	fn schedule(s: u32, ) -> Weight {
		(37_835_000 as Weight)
			.saturating_add((81_000 as Weight).saturating_mul(s as Weight))
			.saturating_add(DbWeight::get().reads(1 as Weight))
			.saturating_add(DbWeight::get().writes(1 as Weight))
	}
	fn cancel(s: u32, ) -> Weight {
		(34_707_000 as Weight)
			.saturating_add((3_125_000 as Weight).saturating_mul(s as Weight))
			.saturating_add(DbWeight::get().reads(1 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
	fn schedule_named(s: u32, ) -> Weight {
		(48_065_000 as Weight)
			.saturating_add((110_000 as Weight).saturating_mul(s as Weight))
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
	fn cancel_named(s: u32, ) -> Weight {
		(38_776_000 as Weight)
			.saturating_add((3_138_000 as Weight).saturating_mul(s as Weight))
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
}
