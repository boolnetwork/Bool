#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use dispatch::DispatchResult;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch, ensure,
    traits::{Currency, Get, LockIdentifier, LockableCurrency, WithdrawReasons},
};
use frame_system::{ensure_root, ensure_signed};
use sp_runtime::{traits::CheckedSub, RuntimeDebug};

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

const THRESHOLD_ID: LockIdentifier = *b"thresh  ";

type GroupIndex = u32;

#[derive(Clone, Eq, PartialEq, Encode, Decode, Default, RuntimeDebug)]
pub struct ThreshPublic(Vec<u8>);

#[derive(Clone, Eq, PartialEq, Encode, Decode, Default, RuntimeDebug)]
pub struct ThreshMode {
    pub t: u32,
    pub n: u32,
}

/// threshold partner state
#[derive(Clone, Eq, PartialEq, Encode, Decode, RuntimeDebug)]
pub enum PartnerState {
    /// sufficient mortgage and no private key escrow
    Standby,
    /// sufficient mortgage and private key escrow
    Running,
    /// the mortgage has been fined and there is no mortgage.
    Offline,
}

impl Default for PartnerState {
    fn default() -> Self {
        PartnerState::Standby
    }
}

/// partner
#[derive(Clone, Eq, PartialEq, Encode, Decode, Default, RuntimeDebug)]
pub struct ThresholdPartner<AccountId, Balance> {
    pub who: AccountId,
    pub active: Balance,
    pub state: PartnerState,
    pub network: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq, Encode, Decode, RuntimeDebug)]
pub enum GroupState {
    Init,
    Working,
    Broken,
}

impl Default for GroupState {
    fn default() -> Self {
        GroupState::Init
    }
}

/// A selected partner group
#[derive(Clone, Eq, PartialEq, Encode, Decode, Default, RuntimeDebug)]
pub struct ThresholdGroup<AccountId> {
    pub id: GroupIndex,
    pub mode: ThreshMode,
    pub partners: Vec<AccountId>,
    pub state: GroupState,
    pub public: ThreshPublic,
}

impl<AccountId> ThresholdGroup<AccountId>
where
    AccountId: PartialEq,
{
    pub fn is_permission(&self, partner: &AccountId) -> bool {
        for p in &self.partners {
            if p == partner {
                return true;
            }
        }
        return false;
    }

    pub fn is_work(&self) -> bool {
        !self.public.0.is_empty()
    }
}

pub type BalanceOf<T> =
    <<T as Trait>::Currency as Currency<<T as frame_system::Trait>::AccountId>>::Balance;

/// Participant account book, join, exit and staking.
/// Do reward and slash.
pub trait Trait: frame_system::Trait {
    type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;

    type Currency: LockableCurrency<Self::AccountId>;
}

decl_storage! {
    trait Store for Module<T: Trait> as Threshold {
        pub MinimumLock get(fn minimum_lock): BalanceOf<T>;

        pub Partner get(fn partner): map hasher(blake2_128_concat) T::AccountId => Option<ThresholdPartner<T::AccountId, BalanceOf<T>>>;
        pub ActivePartners get(fn active_partners) : Vec<T::AccountId>;

        pub GroupCount get(fn group_count): GroupIndex = 0;
        pub TryGroups get(fn try_groups): Vec<GroupIndex>;
        pub Groups get(fn groups): map hasher(blake2_128_concat) GroupIndex => Option<ThresholdGroup<T::AccountId>>;
    }
}

decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as frame_system::Trait>::AccountId,
        Balance = BalanceOf<T>,
    {
        Joined(AccountId, Balance),
        Withdrawn(AccountId, Balance),
        TryGroup(GroupIndex, ThreshMode, Vec<AccountId>),
        Grouped(GroupIndex, ThreshPublic),
        TryExit(AccountId, AccountId),
        Exchanged(GroupIndex, AccountId, AccountId),
        Reward(AccountId, Balance),
        Slash(AccountId, Balance),
        Report(AccountId),
    }
);

decl_error! {
    pub enum Error for Module<T: Trait> {
        InsufficientValue,
        InsufficientBalance,
        InsufficientPartner,
        NotJoined,
        AlreadyJoined,
        NoPermission,
        NoGroup,
        NotWorking,
        NotStandby,
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
            ensure!(value < T::Currency::free_balance(&actor), Error::<T>::InsufficientBalance);

            let item = ThresholdPartner {
                who: actor.clone(),
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

            // TODO get usable balance.
            let actor_balance = T::Currency::free_balance(&actor);

            if let Some(extra) = actor_balance.checked_sub(&partner.active) {
                let extra = extra.min(additional);
                partner.active += extra;
                Self::update_partner(&actor, &partner);
                Self::deposit_event(RawEvent::Joined(actor, extra));
            } else {
                Err(Error::<T>::InsufficientValue)?
            }

            Ok(())
        }

        /// try to genesis key.
        #[weight = 0]
        pub fn try_group(origin, mode: ThreshMode) -> DispatchResult {
            let _actor = ensure_root(origin)?;

            ensure!(mode.n < <ActivePartners<T>>::get().len() as u32, Error::<T>::InsufficientPartner);
            let partners = Self::select_partners(mode.n);

            // update count
            let c = GroupCount::get();
            GroupCount::put(c + 1);

            let group = ThresholdGroup {
                id: c,
                mode: mode.clone(),
                partners: partners.clone(),
                state: GroupState::Init,
                public: Default::default(),
            };

            TryGroups::mutate(|s| { s.push(c); });
            <Groups<T>>::insert(c, group);
            Self::deposit_event(RawEvent::TryGroup(c, mode, partners));

            Ok(())
        }

        // All participants submit the generated public key through this function
        #[weight = 0]
        pub fn group(origin, gi: GroupIndex, public: ThreshPublic, _proof: Vec<u8>) -> DispatchResult {
            let _actor = ensure_signed(origin);

            let try_groups = TryGroups::get();
            if try_groups.is_empty() || !try_groups.contains(&gi){
                Err(Error::<T>::InsufficientPartner)?
            }

            // TODO check proof
            let mut group = <Groups<T>>::get(&gi).ok_or(Error::<T>::NoGroup)?;
            group.public = public.clone();
            <Groups<T>>::insert(gi, group);
            Self::deposit_event(RawEvent::Grouped(gi, public));

            Ok(())
        }

        /// partner should exit firstly, then withdraw balance.
        #[weight = 0]
        pub fn exit(origin, gi: GroupIndex) -> DispatchResult {
            let actor = ensure_signed(origin)?;

            let group = <Groups<T>>::get(&gi).ok_or(Error::<T>::NoGroup)?;
            ensure!(group.is_work(), Error::<T>::NotWorking);

            // select a partner not in group.
            let receiver = Self::select_partner_without_group(gi);

            Self::deposit_event(RawEvent::TryExit(actor, receiver));
            Ok(())
        }

        /// The private key was exchanged successfully and proof was provided
        #[weight = 0]
        pub fn exchange(origin, gi: GroupIndex, ) -> DispatchResult {
            let _actor = ensure_signed(origin)?;
            // TODO
            Ok(())
        }

        #[weight = 0]
        pub fn withdraw(origin) -> DispatchResult {
            let actor = ensure_signed(origin)?;

            let partner = Self::partner(&actor).ok_or(Error::<T>::NotJoined)?;
            ensure!(partner.state == PartnerState::Standby, Error::<T>::NotStandby);

            <Partner<T>>::remove(&actor);
            // remove the lock.
            T::Currency::remove_lock(THRESHOLD_ID, &actor);

            Self::deposit_event(RawEvent::Withdrawn(actor, partner.active));
            Ok(())
        }

        /// Report the partner who committed the crime
        #[weight = 0]
        pub fn blame_report(origin) -> DispatchResult {
            // TODO
            Ok(())
        }
    }
}

impl<T: Trait> Module<T> {
    fn update_partner(partner: &T::AccountId, info: &ThresholdPartner<T::AccountId, BalanceOf<T>>) {
        T::Currency::set_lock(THRESHOLD_ID, &info.who, info.active, WithdrawReasons::all());
        <Partner<T>>::insert(partner, info);
    }

    fn select_partners(n: u32) -> Vec<T::AccountId> {
        // sort by stash
        // or random selection.
        Vec::new()
    }

    fn select_partner_without_group(index: GroupIndex) -> T::AccountId {
        T::AccountId::default()
    }
}
