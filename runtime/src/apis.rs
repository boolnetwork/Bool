use sp_std::vec::Vec;
use bool_primitives::{AccountId, Index};

sp_api::decl_runtime_apis! {
   pub trait VendorApi{
		fn account_nonce(account: &AccountId) -> u64 ;
		// fn is_tss_party(id: &AccountId) -> bool;
	}
}