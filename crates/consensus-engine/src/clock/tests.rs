use super::*;

fn clock() -> SlotClock {
    SlotClock::new(1_700_000_000, 4)
}

#[test]
fn genesis_is_slot_zero() {
    let c = clock();
    assert_eq!(c.timestamp_for(0), c.genesis_time_secs());
    assert_eq!(c.slot_for(c.genesis_time_secs()), 0);
}

#[test]
fn timestamp_for_is_monotonic_per_slot() {
    let c = clock();
    for slot in 0..10 {
        assert_eq!(c.timestamp_for(slot), 1_700_000_000 + slot * 4,);
    }
}

#[test]
fn slot_for_is_inverse_of_timestamp_for() {
    let c = clock();
    for slot in 0..32u64 {
        let t = c.timestamp_for(slot);
        assert_eq!(c.slot_for(t), slot);
    }
}

#[test]
fn slot_for_floors_within_a_slot() {
    let c = clock();
    let t = c.timestamp_for(5);
    assert_eq!(c.slot_for(t + 1), 5);
    assert_eq!(c.slot_for(t + 3), 5);
    assert_eq!(c.slot_for(t + 4), 6);
}

#[test]
fn pre_genesis_timestamp_maps_to_slot_zero() {
    let c = clock();
    assert_eq!(c.slot_for(0), 0);
    assert_eq!(c.slot_for(c.genesis_time_secs() - 1), 0);
}

#[test]
fn slot_for_picks_the_covering_slot() {
    let c = clock();
    assert_eq!(c.slot_for(c.timestamp_for(7) + 1), 7);
}
