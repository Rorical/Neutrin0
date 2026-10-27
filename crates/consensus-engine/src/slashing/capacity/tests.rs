use super::*;

const SMALL: Limits = Limits {
    entries: 8,
    bytes: 100,
};

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "Matches the owner signature."
)]
const fn owner(key: &(u32, u32)) -> u32 {
    key.0
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "Matches the size signature."
)]
const fn weight(size: &usize) -> usize {
    *size
}

fn map() -> Observed<(u32, u32), usize, u32> {
    Observed::new(owner, weight)
}

#[test]
fn a_flooding_owner_displaces_only_its_own_latest_entries() {
    let mut map = map();
    // One honest entry, then a flood from owner 7 well past the cap.
    assert!(map.insert(Some(SMALL), (1, 0), 1));
    for round in 0..100 {
        map.insert(Some(SMALL), (7, round), 1);
    }
    assert_eq!(map.len(), SMALL.entries);
    assert!(map.contains_key(&(1, 0)));
    // The flooder keeps its earliest rounds and cannot push a later one.
    assert!(map.contains_key(&(7, 0)));
    assert!(!map.insert(Some(SMALL), (7, u32::MAX), 1));
    // Another signer is still observed, at the flooder's expense.
    assert!(map.insert(Some(SMALL), (2, 5), 1));
    assert_eq!((map.len(), map.bytes()), (SMALL.entries, SMALL.entries));
    assert!(map.contains_key(&(7, 5)));
    assert!(!map.contains_key(&(7, 6)));
    // The indexes follow every removal.
    map.retain(|key| key.0 != 7);
    assert_eq!(map.len(), 2);
    assert_eq!(map.heaviest_latest(), Some((2, 5)));
}

#[test]
fn sized_maps_make_room_by_bytes_and_reporters_keep_everything() {
    let mut map = map();
    assert!(map.insert(Some(SMALL), (7, 0), 50));
    assert!(map.insert(Some(SMALL), (7, 1), 50));
    assert!(map.insert(Some(SMALL), (1, 0), 1));
    assert!(!map.insert(Some(SMALL), (2, 0), 101));
    assert_eq!(map.bytes(), 51);
    assert!(!map.contains_key(&(7, 1)));
    assert!(map.replace(Some(SMALL), (7, 0), 20));
    assert_eq!(map.bytes(), 21);
    // A replacement too large for the bound keeps the earlier value.
    assert!(!map.replace(Some(SMALL), (7, 0), 101));
    assert_eq!((map.get(&(7, 0)), map.bytes()), (Some(&20), 21));
    let mut unbounded = Observed::new(owner, weight);
    for round in 0..100 {
        unbounded.insert(None, (7, round), 1);
    }
    assert_eq!((unbounded.len(), unbounded.bytes()), (100, 100));
}
