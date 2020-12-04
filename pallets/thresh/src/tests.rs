use crate::{mock::*, Error};
use frame_support::{assert_noop, assert_ok};

#[test]
fn join_should_work_with_low_balance() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Thresh::join(Origin::signed(1), 101),
            Error::<Test>::InsufficientValue
        );
        assert_eq!(Balances::free_balance(1), 100);
        assert_eq!(Balances::usable_balance(1), 100);
    });
}

#[test]
fn join_should_work_with_enough_balance() {
    new_test_ext().execute_with(|| {
        assert_ok!(Thresh::join(Origin::signed(1), 90));
        assert_eq!(Balances::free_balance(1), 100);
        assert_eq!(Balances::usable_balance(1), 10);
        assert_noop!(
            Thresh::join_extra(Origin::signed(1), 11),
            Error::<Test>::InsufficientValue
        );
        assert_ok!(Thresh::join_extra(Origin::signed(1), 10));
    });
}

#[test]
fn group_should_work() {
    new_test_ext().execute_with(|| {});
}
