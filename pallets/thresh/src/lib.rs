#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch, traits::Get};
use frame_system::ensure_signed;
use dispatch::DispatchResult;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

pub struct ThreshPublic(Vec<u8>);

pub struct ThreshMode {
	t: u32,
	n: u32,
}

/// threshold partner state
pub enum PartnerState {
	/// the mortgage has been fined and there is no mortgage.
	Offline,
	/// sufficient mortgage and no private key escrow
	Standby,
	/// sufficient mortgage and private key escrow
	Running,
}

/// partner
pub struct ThresholdPartner<AccountId> {
	pub stash: AccountId,
	pub active: Balance,
	pub state: PartnerState,
}

// A selected partner group
pub struct ThresholdGroup {
	pub mode: ThreshMode,
	pub partners: Vec<AccountId>,
	pub public: ThreshPublic,
}

pub trait Trait: frame_system::Trait {
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

decl_storage! {
	trait Store for Module<T: Trait> as Threshold {
		pub PartnerCount get(fn partner_count) config(): u32;
		pub Partner get(fn partner): map hasher(blake2_128_concat) T::AccountId => Option<ThresholdPartner<<T::AccountId>>;
		pub Groups get(fn groups): Vec<ThresholdGroup>;
	}
}

decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Trait>::AccountId {
		Join(AccountId, Balance),
		Exit(AccountId),
		Reward(AccountId, Balance),
		Slash(AccountId, Balance),
		Report(AccountId),
	}
);

decl_error! {
	pub enum Error for Module<T: Trait> {
		/// Error names should be descriptive.
		,
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;

		/// partner join
		#[weight = 0]
		pub fn join(origin) -> DispatchResult {

		}

		/// withdraw
		#[weight = 0]
		pub fn exit(origin) -> DispatchResult {
			Ok(())
		}

		#[weight = 0]
		pub fn join_extra(origin) -> DispatchResult {
			Ok(())
		}

		/// Report the partner who committed the crime
		#[weight = 0]
		pub fn blame_report(origin) -> DispatchResult {
			Ok(())
		}

		///
		#[weight = 0]
		pub fn group(origin, mode: ThreshMode) -> DispatchResult {

		}
	}
}
