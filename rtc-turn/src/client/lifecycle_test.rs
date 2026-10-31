use super::*;
use sansio::Protocol;
use stun::error_code::CODE_STALE_NONCE;

const RELAY: &str = "127.0.0.1:50000";
const PEER: &str = "127.0.0.2:50001";

/// Creates a live allocation and permission without sockets or wall-clock waits.
fn fixture(now: Instant) -> Result<Client> {
    let mut client = Client::new(
        ClientConfig {
            turn_serv_addr: "127.0.0.1:3478".into(),
            local_addr: "127.0.0.1:40000".parse().unwrap(),
            username: "user".into(),
            password: "password".into(),
            realm: "realm".into(),
            ..Default::default()
        },
        crypto::default_provider().unwrap(),
    )?;
    let relay = RELAY.parse().unwrap();
    client.relays.insert(
        relay,
        RelayState::new(
            now,
            relay,
            vec![1; 16],
            Nonce::new(ATTR_NONCE, "nonce".into()),
            Duration::from_secs(600),
            None,
        ),
    );
    let peer = PEER.parse().unwrap();
    let id = client.relay(relay)?.create_permission(now, peer)?.unwrap();
    let response = response(
        &client,
        id,
        METHOD_CREATE_PERMISSION,
        CLASS_SUCCESS_RESPONSE,
        &[],
        Some(&[1; 16]),
    )?;
    deliver(
        &mut client,
        now,
        &response,
        "127.0.0.1:3478".parse().unwrap(),
    )?;
    while client.poll_write().is_some() {}
    while client.poll_event().is_some() {}
    Ok(client)
}

/// Encodes a response with optional integrity so negative cases exercise the real dispatcher.
fn response(
    client: &Client,
    id: TransactionId,
    method: Method,
    class: MessageClass,
    attrs: &[Box<dyn Setter>],
    key: Option<&[u8]>,
) -> Result<Message> {
    let mut msg = Message::new();
    msg.build(&[Box::new(id), Box::new(MessageType::new(method, class))])?;
    for attr in attrs {
        attr.add_to(&mut msg)?;
    }
    if let Some(key) = key {
        MessageIntegrity::new_raw_integrity_with_provider(
            key.to_vec(),
            client.crypto_provider.crypto(),
        )
        .add_to(&mut msg)?;
    }
    FINGERPRINT.add_to(&mut msg)?;
    Ok(msg)
}

/// Injects the actual transport source along with the encoded TURN packet.
fn deliver(client: &mut Client, now: Instant, msg: &Message, from: SocketAddr) -> Result<()> {
    client.handle_inbound(now, &msg.raw, from)
}

/// Reads the next actual wire message from the client.
fn output(client: &mut Client) -> Result<Message> {
    let mut msg = Message::new();
    msg.raw = client
        .poll_write()
        .expect("queued request or indication")
        .message
        .to_vec();
    msg.decode()?;
    Ok(msg)
}

#[test]
fn refresh_timeout_recovers_the_same_channel_with_indications() -> Result<()> {
    let now = Instant::now();
    let mut client = fixture(now)?;
    let peer = PEER.parse().unwrap();
    let channel = client.binding_mgr.create(now, peer).unwrap().number;
    client
        .binding_mgr
        .get_by_addr(&peer)
        .unwrap()
        .set_state(BindingState::Ready);
    client.relay(RELAY.parse().unwrap())?.send_to(
        now + Duration::from_secs(301),
        b"refresh",
        peer,
    )?;
    let request = output(&mut client)?;
    assert_eq!(request.typ.method, METHOD_CHANNEL_BIND);
    while client.poll_write().is_some() {}
    while client.has_transaction(&request.transaction_id) {
        let deadline = client.tr_map.poll_timout().unwrap();
        client.handle_timeout(deadline)?;
        while client.poll_write().is_some() {}
    }
    assert!(!client.has_transaction(&request.transaction_id));
    client.relay(RELAY.parse().unwrap())?.send_to(
        now + Duration::from_secs(601),
        b"recover",
        peer,
    )?;
    let bind = output(&mut client)?;
    assert_eq!(bind.typ.method, METHOD_CHANNEL_BIND);
    let mut number = ChannelNumber::default();
    number.get_from(&bind)?;
    assert_eq!(number.0, channel);
    assert_eq!(
        output(&mut client)?.typ,
        MessageType::new(METHOD_SEND, CLASS_INDICATION)
    );
    Ok(())
}

#[test]
fn stale_nonce_retries_refresh_and_close_with_original_lifetime() -> Result<()> {
    for (lifetime, signed) in [
        (Duration::from_secs(600), true),
        (Duration::ZERO, true),
        (Duration::from_secs(600), false),
        (Duration::ZERO, false),
    ] {
        let now = Instant::now();
        let mut client = fixture(now)?;
        client
            .relay(RELAY.parse().unwrap())?
            .refresh_allocation(now, lifetime)?;
        let request = output(&mut client)?;
        let challenge = response(
            &client,
            request.transaction_id,
            METHOD_REFRESH,
            CLASS_ERROR_RESPONSE,
            &[
                Box::new(CODE_STALE_NONCE),
                Box::new(Nonce::new(ATTR_NONCE, "new-nonce".into())),
                Box::new(Realm::new(ATTR_REALM, "realm".into())),
            ],
            signed.then_some([1; 16].as_slice()),
        )?;
        deliver(&mut client, now, &challenge, client_server())?;
        let mut retry = output(&mut client)?;
        assert_ne!(retry.transaction_id, request.transaction_id);
        assert_eq!(retry.typ.method, METHOD_REFRESH);
        let mut requested = Lifetime::default();
        requested.get_from(&retry)?;
        assert_eq!(requested.0, lifetime);
        assert_eq!(Nonce::get_from_as(&retry, ATTR_NONCE)?.text, "new-nonce");
        MessageIntegrity::check(&mut retry, &[1; 16], client.crypto_provider.crypto())?;
    }
    Ok(())
}

/// Returns the numeric fixture server without DNS.
fn client_server() -> SocketAddr {
    "127.0.0.1:3478".parse().unwrap()
}

#[test]
fn only_server_data_for_a_live_allocation_reaches_the_application() -> Result<()> {
    let now = Instant::now();
    let mut client = fixture(now)?;
    let peer: SocketAddr = PEER.parse().unwrap();
    let data = response(
        &client,
        TransactionId::new(),
        METHOD_DATA,
        CLASS_INDICATION,
        &[
            Box::new(PeerAddress {
                ip: peer.ip(),
                port: peer.port(),
            }),
            Box::new(Data(b"data".to_vec())),
        ],
        None,
    )?;
    let number = client.binding_mgr.create(now, peer).unwrap().number;
    let mut channel = ChannelData {
        data: b"data".to_vec(),
        number: ChannelNumber(number),
        ..Default::default()
    };
    channel.encode();
    for raw in [&data.raw, &channel.raw] {
        let _ = client.handle_inbound(now, raw, "127.0.0.3:3478".parse().unwrap());
        assert!(
            client.poll_event().is_none(),
            "unrelated sender must not inject data"
        );
        client.handle_inbound(now, raw, client_server())?;
        assert!(matches!(
            client.poll_event(),
            Some(Event::DataIndicationOrChannelData(..))
        ));
    }
    client.relays.clear();
    for raw in [&data.raw, &channel.raw] {
        let _ = client.handle_inbound(now, raw, client_server());
        assert!(
            client.poll_event().is_none(),
            "data requires an active allocation"
        );
    }
    Ok(())
}

#[test]
fn unauthenticated_responses_preserve_pending_transactions() -> Result<()> {
    let now = Instant::now();
    for method in [
        METHOD_REFRESH,
        METHOD_CREATE_PERMISSION,
        METHOD_CHANNEL_BIND,
    ] {
        for key in [None, Some([2; 16].as_slice())] {
            let mut client = fixture(now)?;
            let relay = RELAY.parse().unwrap();
            let peer = PEER.parse().unwrap();
            let id = match method {
                METHOD_REFRESH => {
                    client.relay(relay)?.close(now)?;
                    output(&mut client)?.transaction_id
                }
                METHOD_CREATE_PERMISSION => {
                    let other = "127.0.0.3:50002".parse().unwrap();
                    let id = client.relay(relay)?.create_permission(now, other)?.unwrap();
                    output(&mut client)?;
                    id
                }
                _ => {
                    client.relay(relay)?.send_to(now, b"bind", peer)?;
                    let request = output(&mut client)?;
                    while client.poll_write().is_some() {}
                    request.transaction_id
                }
            };
            let attrs: Vec<Box<dyn Setter>> = if method == METHOD_REFRESH {
                vec![Box::new(Lifetime(Duration::ZERO))]
            } else {
                vec![]
            };
            let invalid = response(&client, id, method, CLASS_SUCCESS_RESPONSE, &attrs, key)?;
            let _ = deliver(&mut client, now, &invalid, client_server());
            assert!(
                client.has_transaction(&id),
                "invalid response consumed {method}"
            );
            assert!(client.relays.contains_key(&relay));
            assert!(client.poll_event().is_none());
            let valid = response(
                &client,
                id,
                method,
                CLASS_SUCCESS_RESPONSE,
                &attrs,
                Some(&[1; 16]),
            )?;
            deliver(&mut client, now, &valid, client_server())?;
            assert!(!client.has_transaction(&id));
        }
    }
    Ok(())
}

#[test]
fn short_integrity_is_rejected_without_consuming_the_transaction() -> Result<()> {
    let now = Instant::now();
    let mut client = fixture(now)?;
    client.relay(RELAY.parse().unwrap())?.close(now)?;
    let request = output(&mut client)?;
    let mut malformed = response(
        &client,
        request.transaction_id,
        METHOD_REFRESH,
        CLASS_SUCCESS_RESPONSE,
        &[],
        None,
    )?;
    malformed.add(ATTR_MESSAGE_INTEGRITY, &[]);
    assert!(deliver(&mut client, now, &malformed, client_server()).is_err());
    assert!(client.has_transaction(&request.transaction_id));
    Ok(())
}

#[test]
fn channel_exhaustion_uses_send_indication() -> Result<()> {
    let now = Instant::now();
    let mut client = fixture(now)?;
    let first: SocketAddr = "127.0.0.4:1".parse().unwrap();
    for port in 1..=4096 {
        client
            .binding_mgr
            .create(now, SocketAddr::new(first.ip(), port))
            .unwrap();
    }
    let original = *client.binding_mgr.find_by_addr(&first).unwrap();
    client
        .relay(RELAY.parse().unwrap())?
        .send_to(now, b"overflow", PEER.parse().unwrap())?;
    assert_eq!(
        output(&mut client)?.typ,
        MessageType::new(METHOD_SEND, CLASS_INDICATION)
    );
    assert_eq!(client.binding_mgr.size(), 4096);
    assert_eq!(client.binding_mgr.find_by_addr(&first), Some(&original));
    Ok(())
}

#[test]
fn close_cancels_all_activity_and_pending_output() -> Result<()> {
    let now = Instant::now();
    let mut client = fixture(now)?;
    client
        .relay(RELAY.parse().unwrap())?
        .send_to(now, b"queued", PEER.parse().unwrap())?;
    client.close()?;
    assert!(client.poll_timeout().is_none());
    assert!(client.poll_write().is_none());
    assert!(client.poll_event().is_none());
    assert!(client.relay(RELAY.parse().unwrap()).is_err());
    assert_eq!(client.binding_mgr.size(), 0);
    client.handle_timeout(now + Duration::from_secs(1000))?;
    assert!(client.poll_timeout().is_none());
    assert!(client.poll_write().is_none());
    Ok(())
}

#[test]
fn mismatched_method_or_source_does_not_consume_binding_transaction() -> Result<()> {
    let now = Instant::now();
    let mut client = fixture(now)?;
    let id = client.send_binding_request_to(now, client_server())?;
    output(&mut client)?;
    let wrong = response(
        &client,
        id,
        METHOD_REFRESH,
        CLASS_SUCCESS_RESPONSE,
        &[],
        None,
    )?;
    let _ = deliver(&mut client, now, &wrong, client_server());
    assert!(client.has_transaction(&id));
    assert!(client.poll_event().is_none());
    let valid = response(
        &client,
        id,
        METHOD_BINDING,
        CLASS_SUCCESS_RESPONSE,
        &[Box::new(XorMappedAddress {
            ip: client.local_addr.ip(),
            port: client.local_addr.port(),
        })],
        None,
    )?;
    let _ = deliver(&mut client, now, &valid, "127.0.0.3:3478".parse().unwrap());
    assert!(client.has_transaction(&id));
    deliver(&mut client, now, &valid, client_server())?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::BindingResponse(..))
    ));
    Ok(())
}

#[test]
#[ignore = "manual throughput measurement"]
fn benchmark_client_data_paths() -> Result<()> {
    let now = Instant::now();
    let mut client = fixture(now)?;
    let peer = PEER.parse().unwrap();
    let number = client.binding_mgr.create(now, peer).unwrap().number;
    client
        .binding_mgr
        .get_by_addr(&peer)
        .unwrap()
        .set_state(BindingState::Ready);
    let mut channel = ChannelData {
        data: vec![42; 1200],
        number: ChannelNumber(number),
        ..Default::default()
    };
    channel.encode();
    let data = response(
        &client,
        TransactionId::new(),
        METHOD_DATA,
        CLASS_INDICATION,
        &[
            Box::new(PeerAddress {
                ip: peer.ip(),
                port: peer.port(),
            }),
            Box::new(Data(vec![42; 1200])),
        ],
        None,
    )?;
    for (name, raw) in [
        ("channel_receive", channel.raw),
        ("indication_receive", data.raw),
    ] {
        let start = Instant::now();
        for _ in 0..200_000 {
            client.handle_inbound(now, std::hint::black_box(&raw), client_server())?;
            std::hint::black_box(client.poll_event().unwrap());
        }
        eprintln!(
            "{name}: {:.1} ns/op",
            start.elapsed().as_nanos() as f64 / 200_000.0
        );
    }
    let payload = [42; 1200];
    let start = Instant::now();
    for _ in 0..200_000 {
        client
            .relay(RELAY.parse().unwrap())?
            .send_to(now, std::hint::black_box(&payload), peer)?;
        std::hint::black_box(client.poll_write().unwrap());
    }
    eprintln!(
        "channel_send: {:.1} ns/op",
        start.elapsed().as_nanos() as f64 / 200_000.0
    );
    Ok(())
}
