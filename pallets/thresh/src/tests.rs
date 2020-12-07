use crate::{mock::*, Error, ThreshMode, ThreshPublic};
use frame_support::{assert_noop, assert_ok, dispatch::DispatchError};
use frame_system::{RawOrigin};

const TEST_ACCOUNT: u64 = 5;

#[test]
fn join_should_work_with_low_balance() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Thresh::join(Origin::signed(TEST_ACCOUNT), 101),
            Error::<Test>::InsufficientBalance
        );
        assert_eq!(Balances::free_balance(TEST_ACCOUNT), 100);
        assert_eq!(Balances::usable_balance(TEST_ACCOUNT), 100);
    });
}

#[test]
fn join_should_work_with_enough_balance() {
    new_test_ext().execute_with(|| {
        assert_ok!(Thresh::join(Origin::signed(TEST_ACCOUNT), 90));
        assert_eq!(Balances::free_balance(TEST_ACCOUNT), 100);
        assert_eq!(Balances::usable_balance(TEST_ACCOUNT), 10);
        // assert_noop!(
        //     Thresh::join_extra(Origin::signed(TestAccount), 11),
        //     Error::<Test>::InsufficientValue
        // );

        // lock another 10.
        assert_ok!(Thresh::join_extra(Origin::signed(TEST_ACCOUNT), 10));
        // usable is 0.
        assert_eq!(Balances::usable_balance(TEST_ACCOUNT), 0);
        assert_eq!(Thresh::active_partners().len(), ACTIVE_COUNT + 1);
    });
}

#[test]
fn withdraw_should_work() {
    new_test_ext().execute_with(|| {
        assert_ok!(Thresh::join(Origin::signed(TEST_ACCOUNT), 90));

        assert_ok!(Thresh::withdraw(Origin::signed(TEST_ACCOUNT)));

        // the partner will remove from list if do withdraw.
        assert_eq!(Thresh::active_partners().len(), ACTIVE_COUNT);
        assert_eq!(Balances::free_balance(TEST_ACCOUNT), 100);
        assert_eq!(Balances::usable_balance(TEST_ACCOUNT), 100);
    });
}

#[test]
fn group_failed_if_unexpected() {
    new_test_ext().execute_with(|| {
        let mode = ThreshMode { t: 1, n: ACTIVE_COUNT as u32 + 1 };
        // only root can use it.
        assert_noop!(
            Thresh::try_group(Origin::signed(1), mode.clone()),
            DispatchError::BadOrigin
        );

        // failed if no partner
        assert_noop!(
            Thresh::try_group(RawOrigin::Root.into(), mode.clone()),
            Error::<Test>::InsufficientPartner
        );

        // failed if no try group
        assert_noop!(
            Thresh::group(Origin::signed(TEST_ACCOUNT), 1, ThreshPublic(vec![0x00]), vec![0x00]),
            Error::<Test>::InsufficientPartner
        );
    });
}

#[test]
fn group_should_work() {
    new_test_ext().execute_with(|| {
        // try group on chain
        let mode = ThreshMode { t: 1, n: 3 };
        assert_ok!(Thresh::try_group(RawOrigin::Root.into(), mode));
        // check state
        assert_eq!(Thresh::try_groups().len(), 1);
        assert_eq!(Thresh::group_count(), 1);

        assert_noop!(Thresh::group(
            Origin::signed(1),
            1,
            ThreshPublic(vec![0x00]),
            vec![0x00]
        ), Error::<Test>::NotTryGroup);

        // submit off chain proof
        assert_ok!(Thresh::group(
            Origin::signed(1),
            0,
            ThreshPublic(vec![0x00]),
            vec![0x00]
        ));


    });
}

#[test]
fn exit_group_should_work() {
    new_test_ext().execute_with(|| {
        // try group on chain
        let mode = ThreshMode { t: 1, n: 3 };
        assert_ok!(Thresh::try_group(RawOrigin::Root.into(), mode.clone()));
        // check state
        assert_eq!(Thresh::try_groups().len(), 1);
        assert_eq!(Thresh::group_count(), 1);
        // submit
        assert_ok!(Thresh::group(
            Origin::signed(1),
            0,
            ThreshPublic(vec![0x00]),
            vec![0x00]
        ));

        assert_ok!(Thresh::exit(Origin::signed(1), 0));

    });
}
