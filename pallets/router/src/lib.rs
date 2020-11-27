#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch, traits::Get};
use frame_system::ensure_signed;
use dispatch::DispatchResult;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

pub struct RoutingRule(Vec<u8>);


pub trait Trait: frame_system::Trait {
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

decl_storage! {
	trait Store for Module<T: Trait> as Router {
		pub Rules get (fn rules): Vec<RoutingRule>;
	}
}

decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Trait>::AccountId {
	}
);

decl_error! {
	pub enum Error for Module<T: Trait> {
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;

		#[weight = 0]
		pub fn register(origin, ) -> DispatchResult {
			let who = ensure_signed(origin)?;
			Ok(())
		}

		#[weight = 0]
		pub fn route(origin, message: Vec<u8>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			Self::do_route();
			Ok(())
		}
	}
}

impl<T: Trait> Module<T> {
	pub fn do_route(message: Vec<u8>) -> bool {
		return true;
	}
}
