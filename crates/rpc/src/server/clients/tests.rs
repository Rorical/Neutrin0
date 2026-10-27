use super::*;

#[test]
fn clients_are_bounded_and_trusted_proxies_name_their_last_hop() {
    let proxy: IpAddr = "10.0.0.1".parse().unwrap();
    let peer: IpAddr = "192.0.2.7".parse().unwrap();
    let clients = Clients::new(&[proxy], 6, 2, 1);
    let first = clients.admit(peer).unwrap();
    // The same address mapped into IPv6 is the same client.
    let _second = clients.admit("::ffff:192.0.2.7".parse().unwrap()).unwrap();
    assert!(clients.admit(peer).is_none());
    drop(first);
    assert!(clients.admit(peer).is_some());
    // One IPv6 /64 is one client.
    let _subscriber = clients.admit("2001:db8::1".parse().unwrap()).unwrap();
    let _neighbour = clients.admit("2001:db8::2".parse().unwrap()).unwrap();
    assert!(clients.admit("2001:db8::3".parse().unwrap()).is_none());
    assert!(clients.admit("2001:db8:0:1::1".parse().unwrap()).is_some());
    // A proxy is bounded only by the listener's six slots, three of them
    // held by the clients above.
    let proxied = [(); 4].map(|()| clients.admit(proxy));
    assert_eq!(
        proxied.iter().filter(|admitted| admitted.is_some()).count(),
        3
    );

    let mut headers = http::HeaderMap::new();
    headers.append(
        "x-forwarded-for",
        "203.0.113.9, 198.51.100.4".parse().unwrap(),
    );
    assert_eq!(
        clients.client(proxy, &headers),
        ClientIp("198.51.100.4".parse().unwrap())
    );
    // Only a trusted proxy's header counts.
    assert_eq!(clients.client(peer, &headers), ClientIp(peer));
    assert_eq!(
        clients.client(proxy, &http::HeaderMap::new()),
        ClientIp(proxy)
    );

    let session = clients.websocket().unwrap();
    assert!(clients.websocket().is_none());
    drop(session);
    assert!(clients.websocket().is_some());
}

#[test]
fn one_client_cannot_hold_every_slot() {
    let slots = ClientSlots::new(4, 2);
    let first = ClientIp("192.0.2.1".parse().unwrap());
    let second = ClientIp("192.0.2.2".parse().unwrap());
    let a = slots.acquire(Some(first)).unwrap();
    let _b = slots.acquire(Some(first)).unwrap();
    assert!(slots.acquire(Some(first)).is_none());
    let _c = slots.acquire(Some(second)).unwrap();
    drop(a);
    assert!(slots.acquire(Some(first)).is_some());
}
