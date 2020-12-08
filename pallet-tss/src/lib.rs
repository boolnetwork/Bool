#![cfg_attr(not(feature = "std"), no_std)]

use sp_std::{prelude::*};

use frame_support::{
    decl_event, decl_module, decl_storage, dispatch::DispatchResult, StorageValue,
    dispatch::DispatchError
};
use frame_system::{self as system, ensure_root};
use pallet_timestamp as timestamp;

pub trait Trait: system::Trait + timestamp::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_storage! {
    trait Store for Module<T: Trait> as Tss {
        Index get(fn index): u64 ;
        Members get(fn members): Vec<T::AccountId>;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        /// start to create a tss key pair
        #[weight = 0]
        fn key_gen(origin, store:Vec<u8>, n: u16, t: u16) -> DispatchResult{
            let _sender = ensure_root(origin)?;
            Self::gen_key(store, n, t)
        }

         #[weight = 0]
        fn sign_mission(origin, store:Vec<u8>, n: u16, t: u16, message_str: Vec<u8>) -> DispatchResult{
            let _sender = ensure_root(origin)?;
            Self::sign(store, n, t, message_str)
        }
    }
}

decl_event!(
    pub enum Event<T>
    where
        // AccountId = <T as system::Trait>::AccountId,
        Time = <T as timestamp::Trait>::Moment,
    {
        /// (index, store, n, t, time)
        GenKey(u64, Vec<u8>, u16, u16, Time),
        /// (index, store, n, t, message_str, time)
        Sign(u64, Vec<u8>, u16, u16, Vec<u8>, Time),
    }
);


impl<T: Trait> Module<T> {
    fn tss_index() -> u64 {
        let index_old = Index::get() + 1;
        Index::put(index_old);
        index_old
    }

    pub fn gen_key(store:Vec<u8>, n: u16, t: u16) -> DispatchResult{
        let index = Self::tss_index();
        let time = <timestamp::Module<T>>::get();
        Self::deposit_event(RawEvent::GenKey(index, store, n, t, time));
        Ok(())
    }

    pub fn sign(store:Vec<u8>, n: u16, t: u16, message_str: Vec<u8>) -> DispatchResult{
        let index = Self::tss_index();
        let time = <timestamp::Module<T>>::get();
        Self::deposit_event(RawEvent::Sign(index, store, n, t, message_str, time));
        Ok(())
    }
}
