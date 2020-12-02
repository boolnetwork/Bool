#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Encode, Decode};
use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch,
	traits::{Get, Currency, WithdrawReasons, LockIdentifier, LockableCurrency}
};
use frame_system::{ensure_signed, ensure_root};
use dispatch::DispatchResult;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

const THRESHOLD_ID: LockIdentifier = *b"thresh  ";

#[derive(Clone, Eq, PartialEq, Encode, Decode, Default, RuntimeDebug)]
pub struct ThreshPublic(Vec<u8>);

#[derive(Clone, Eq, PartialEq, Encode, Decode, Default, RuntimeDebug)]
pub struct ThreshMode {
	t: u32,
	n: u32,
}

/// threshold partner state
#[derive(Clone, Eq, PartialEq, Encode, Decode, Default, RuntimeDebug)]
pub enum PartnerState {
	/// the mortgage has been fined and there is no mortgage.
	Offline,
	/// sufficient mortgage and no private key escrow
	Standby,
	/// sufficient mortgage and private key escrow
	Running,
}

/// partner
#[derive(Clone, Eq, PartialEq, Encode, Decode, Default, RuntimeDebug)]
pub struct ThresholdPartner<AccountId, Balance> {
	pub who: AccountId,
	pub active: Balance,
	pub state: PartnerState,
	pub network: Vec<u8>,
}

//TODO maybe add group id for index.
/// A selected partner group
#[derive(Clone, Eq, PartialEq, Encode, Decode, Default, RuntimeDebug)]
pub struct ThresholdGroup<AccountId> {
	pub id: u32,
	pub mode: ThreshMode,
	pub partners: Vec<AccountId>,
	pub public: ThreshPublic,
}

pub type BalanceOf<T> = <<T as Trait>::Currency as Currency<<T as frame_system::Trait>::AccountId>>::Balance;

/// Participant account book, join, exit and staking.
/// Do reward and slash.
pub trait Trait: frame_system::Trait {
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

decl_storage! {
	trait Store for Module<T: Trait> as Threshold {
		pub MinimumLock get(fn minimum_lock): BalanceOf<T>;
		pub PartnerCount get(fn partner_count) config(): u32;
		pub Partner get(fn partner): map hasher(blake2_128_concat) T::AccountId => Option<ThresholdPartner<<T::AccountId>>;
		pub TryGroups get(fn try_groups): Vec<ThresholdGroup>;
		pub Groups get(fn groups): map hasher(blake2_128_concat) ThreshPublic => Option<ThresholdGroup<T::AccountId>>;
	}
}

decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Trait>::AccountId {
		Joined(AccountId, Balance),
		TryGroup(id),
		Grouped(id, ThreshPublic),
		Exit(AccountId),
		Reward(AccountId, Balance),
		Slash(AccountId, Balance),
		Report(AccountId),
	}
);

decl_error! {
	pub enum Error for Module<T: Trait> {
		InsufficientValue,
		InsufficientBalance,
		NotJoined,
		AlreadyJoined,
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;

		/// partner join
		#[weight = 0]
		pub fn join(origin, value: BalanceOf<T>) -> DispatchResult {
			let actor = ensure_signed(origin)?;

			ensure!(!<Partner<T>>::contains_key(&actor), Error::<T>::AlreadyJoined);
			ensure!(value > <MinimumLock<T>>::get(), Error::<T>::InsufficientValue);
			ensure!(value > T::Currency::minimum_balance(), Error::<T>::InsufficientBalance);

			let item = ThresholdPartner {
				who: actor,
				active: value,
				state: PartnerState::Standby,
				network: Vec::new(),
			};

			Self::update_partner(&actor, &item);
			Self::deposit_event(RawEvent::Joined(actor, value));
			Ok(())
		}

		#[weight = 0]
		pub fn join_extra(origin, additional: BalanceOf<T>) -> DispatchResult {
			let actor = ensure_signed(origin)?;

			let mut partner = Self::partner(&actor).ok_or(Error::<T>::NotJoined)?;

			let actor_balance = T::Currency::free_balance(&actor);

			if let Some(extra) = actor_balance.checked_sub(&partner.active) {
				let extra = extra.min(additional);
				partner.active += extra;
				Self::update_partner(&actor, &ledger);
				Self::deposit_event(RawEvent::Joined(actor, extra));
			}

			Ok(())
		}

		/// try to genesis key.
		#[weight = 0]
		pub fn try_group(origin, mode: ThreshMode) -> DispatchResult {
			let _actor = ensure_root(origin)?;

			/// select partners
			let
			Ok(())
		}

		#[weight = 0]
		pub fn group(origin) -> DispatchResult {

		}

		/// partner should exit firstly, then withdraw balance.
		#[weight = 0]
		pub fn exit(origin) -> DispatchResult {
			let partner = ensure_signed(origin)?;
			Ok(())
		}

		#[weight = 0]
		pub fn exchanged(origin) -> DispatchResult {
			let partner = ensure_signed(origin)?;
			Ok(())
		}

		#[weight = 0]
		pub fn withdraw(origin) -> DispatchResult {
			let partner = ensure_signed(origin)?;
			Ok(())
		}

		/// Report the partner who committed the crime
		#[weight = 0]
		pub fn blame_report(origin) -> DispatchResult {
			Ok(())
		}

	}
}

impl<T: Trait> Module<T> {
	fn update_partner(
		partner: &T::AccountId,
		info: &ThresholdPartner<T::AccountId, BalanceOf<T>>
	) {
		T::Currency::set_lock(
			THRESHOLD_ID,
			&info.who,
			info.active,
			WithdrawReasons::all(),
		);
		<Partner<T>>::insert(partner, info);
	}
}
