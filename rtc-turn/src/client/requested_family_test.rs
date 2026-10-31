//! Actual allocation transactions preserve relay family independently of their carrier.

use super::*;
use sansio::Protocol;
use stun::error_code::CODE_UNAUTHORIZED;

const USER: &str = "family-user";
const PASSWORD: &str = "family-password";
const REALM: &str = "family-fixture.invalid";
const NONCE: &str = "family-nonce";

/// Decodes the actual client output and checks the original UDP allocation contract.
fn allocation_request(
    client: &mut Client,
    protocol: TransportProtocol,
    family: Option<u8>,
) -> Result<Message> {
    let output = client.poll_write().expect("an actual Allocate request");
    assert_eq!(output.transport.transport_protocol, protocol);
    let mut request = Message::new();
    request.raw = output.message.to_vec();
    request.decode()?;
    assert_eq!(
        request.typ,
        MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST)
    );
    let mut requested_transport = RequestedTransport::default();
    requested_transport.get_from(&request)?;
    assert_eq!(requested_transport.protocol, PROTO_UDP);
    match family {
        Some(expected) => {
            let mut actual = RequestedAddressFamily::default();
            actual.get_from(&request)?;
            assert_eq!(actual.0, expected);
            let position = |kind| {
                request
                    .attributes
                    .0
                    .iter()
                    .position(|attribute| attribute.typ == kind)
                    .unwrap()
            };
            let protected_by = if request.get(ATTR_MESSAGE_INTEGRITY).is_ok() {
                ATTR_MESSAGE_INTEGRITY
            } else {
                ATTR_FINGERPRINT
            };
            assert!(position(ATTR_REQUESTED_ADDRESS_FAMILY) < position(protected_by));
        }
        None => assert!(request.get(ATTR_REQUESTED_ADDRESS_FAMILY).is_err()),
    }
    FINGERPRINT.check(&request)?;
    Ok(request)
}

/// Delivers an encoded response to the original request owner without sockets or ambient time.
fn deliver(client: &mut Client, now: Instant, response: Message) -> Result<()> {
    client.handle_read(TransportMessage {
        now,
        transport: TransportContext {
            local_addr: client.local_addr,
            peer_addr: client.turn_server_addr()?,
            transport_protocol: client.transport_protocol,
            ecn: None,
        },
        message: BytesMut::from(response.raw.as_slice()),
    })
}

/// Both Allocate attempts retain the selection, transaction correlation and real integrity.
#[test]
fn test_requested_family_is_retained_by_actual_allocation_transactions() -> Result<()> {
    let outer_v4: SocketAddr = "127.0.0.1:50000".parse().unwrap();
    let outer_v6: SocketAddr = "[::1]:50000".parse().unwrap();
    for (selected, protocol, local) in [
        (None, TransportProtocol::UDP, outer_v6),
        (
            Some(REQUESTED_FAMILY_IPV4),
            TransportProtocol::TCP,
            outer_v6,
        ),
        (
            Some(REQUESTED_FAMILY_IPV6),
            TransportProtocol::UDP,
            outer_v4,
        ),
        (
            Some(REQUESTED_FAMILY_IPV6),
            TransportProtocol::TCP,
            outer_v6,
        ),
    ] {
        let expected = selected
            .as_ref()
            .and_then(|family| (*family == REQUESTED_FAMILY_IPV6).then_some(family.0));
        let provider = crypto::default_provider().expect("the selected test crypto provider");
        let mut client = Client::new(
            ClientConfig {
                turn_serv_addr: SocketAddr::new(local.ip(), 3478).to_string(),
                local_addr: local,
                transport_protocol: protocol,
                requested_address_family: selected,
                username: USER.into(),
                password: PASSWORD.into(),
                ..Default::default()
            },
            provider.clone(),
        )?;
        let now = Instant::now();
        let receipt = client.allocate(now)?;
        let initial = allocation_request(&mut client, protocol, expected)?;
        assert!(client.has_transaction(&initial.transaction_id));
        let mut challenge = Message::new();
        challenge.build(&[
            Box::new(initial.transaction_id),
            Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE)),
            Box::new(CODE_UNAUTHORIZED),
            Box::new(Realm::new(ATTR_REALM, REALM.into())),
            Box::new(Nonce::new(ATTR_NONCE, NONCE.into())),
            Box::new(FINGERPRINT),
        ])?;
        deliver(&mut client, now, challenge)?;
        assert!(!client.has_transaction(&initial.transaction_id));
        let mut authenticated = allocation_request(&mut client, protocol, expected)?;
        assert_eq!(authenticated.transaction_id, receipt);
        assert!(client.has_transaction(&receipt));
        let key = MessageIntegrity::long_term_integrity_key(
            USER.into(),
            REALM.into(),
            PASSWORD.into(),
            provider.crypto(),
        )?;
        MessageIntegrity::check(&mut authenticated, &key, provider.crypto())?;

        let relay = SocketAddr::new(
            if expected == Some(REQUESTED_FAMILY_IPV6.0) {
                "2001:db8::80".parse().unwrap()
            } else {
                "192.0.2.80".parse().unwrap()
            },
            50001,
        );
        let mut response = Message::new();
        response.build(&[
            Box::new(receipt),
            Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_SUCCESS_RESPONSE)),
            Box::new(RelayedAddress {
                ip: relay.ip(),
                port: relay.port(),
            }),
            Box::new(Lifetime(Duration::from_secs(600))),
            Box::new(MessageIntegrity::new_raw_integrity_with_provider(
                key,
                provider.crypto(),
            )),
            Box::new(FINGERPRINT),
        ])?;
        deliver(&mut client, now, response)?;
        assert!(
            matches!(client.poll_event(), Some(Event::AllocateResponse(id, address))
            if id == receipt && address == relay)
        );
        assert!(!client.has_transaction(&receipt));
        assert!(client.poll_event().is_none());
        client.close()?;
    }
    Ok(())
}

/// An invalid codec selector is rejected before even malformed endpoint parsing can run.
#[test]
fn test_invalid_requested_family_precedes_endpoint_resolution() {
    for family in [0, 3, u8::MAX] {
        let result = Client::new(
            ClientConfig {
                stun_serv_addr: "[::1".into(),
                requested_address_family: Some(RequestedAddressFamily(family)),
                ..Default::default()
            },
            crypto::default_provider().expect("the selected test crypto provider"),
        );
        assert!(
            matches!(result, Err(Error::Other(message)) if message == "invalid requested address family")
        );
    }
}
