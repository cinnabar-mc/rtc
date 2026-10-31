//! Stateful, bounded restart cookies for an existing single-transport association.
use super::*;
use crate::param::param_type::ParamType;
use crate::queue::reassembly_queue::ReassemblyQueue;

pub(super) struct RestartCandidate {
    cookie: ParamStateCookie,
    peer_init: ChunkInit,
    issued: Instant,
    local_tag: u32,
    local_tsn: u32,
    local_tie_tag: u32,
    peer_tie_tag: u32,
}

impl Association {
    /// Challenges a restart without changing live tags, streams, queues or timers.
    pub(super) fn handle_restart_init(
        &mut self,
        packet: &Packet,
        init: &ChunkInit,
        now: Instant,
    ) -> Result<Vec<Packet>> {
        if !matches!(
            self.state,
            AssociationState::Established
                | AssociationState::ShutdownPending
                | AssociationState::ShutdownSent
                | AssociationState::ShutdownReceived
        ) || packet.common_header.source_port != self.destination_port
            || packet.common_header.destination_port != self.source_port
            || init.initiate_tag == self.peer_verification_tag
            || init.params.iter().any(|param| {
                matches!(
                    param.header().typ,
                    ParamType::Ipv4Addr | ParamType::Ipv6Addr | ParamType::HostNameAddr
                )
            })
        {
            return Ok(vec![]);
        }
        let duplicate = if let Some(candidate) = &self.pending_restart {
            now >= candidate.issued
                && now.duration_since(candidate.issued) <= Duration::from_secs(60)
                && candidate.local_tie_tag == self.my_verification_tag
                && candidate.peer_tie_tag == self.peer_verification_tag
                && candidate.peer_init.marshal()? == init.marshal()?
        } else {
            false
        };
        if !duplicate {
            // Keep one proposal, but retransmit the same challenge for duplicate INITs.
            let mut tag = random::<u32>();
            while tag == 0 || tag == self.my_verification_tag {
                tag = random::<u32>();
            }
            self.pending_restart = Some(Box::new(RestartCandidate {
                cookie: ParamStateCookie::new(),
                peer_init: init.clone(),
                issued: now,
                local_tag: tag,
                local_tsn: self.my_next_tsn,
                local_tie_tag: self.my_verification_tag,
                peer_tie_tag: self.peer_verification_tag,
            }));
        }
        let candidate = self.pending_restart.as_ref().unwrap();
        let mut ack = ChunkInit {
            is_ack: true,
            initiate_tag: candidate.local_tag,
            initial_tsn: candidate.local_tsn,
            num_inbound_streams: self
                .my_max_num_inbound_streams
                .min(init.num_outbound_streams),
            num_outbound_streams: self
                .my_max_num_outbound_streams
                .min(init.num_inbound_streams),
            advertised_receiver_window_credit: self.max_receive_buffer_size,
            params: vec![Box::new(candidate.cookie.clone())],
        };
        ack.set_supported_extensions();
        Ok(vec![Packet {
            common_header: CommonHeader {
                source_port: self.source_port,
                destination_port: self.destination_port,
                verification_tag: init.initiate_tag,
            },
            chunks: vec![Box::new(ack)],
        }])
    }

    /// Installs a new generation only after its cookie, tie-tags, tuple and lifetime match.
    pub(super) fn accept_restart_cookie(
        &mut self,
        packet: &Packet,
        echo: &ChunkCookieEcho,
        now: Instant,
    ) -> Result<bool> {
        if !matches!(
            self.state,
            AssociationState::Established
                | AssociationState::ShutdownPending
                | AssociationState::ShutdownSent
                | AssociationState::ShutdownReceived
        ) {
            return Ok(false);
        }
        let Some(candidate) = &self.pending_restart else {
            return Ok(false);
        };
        if !constant_time_eq(&candidate.cookie.cookie, &echo.cookie)
            || packet.common_header.verification_tag != candidate.local_tag
            || packet.common_header.source_port != self.destination_port
            || packet.common_header.destination_port != self.source_port
            || candidate.local_tie_tag != self.my_verification_tag
            || candidate.peer_tie_tag != self.peer_verification_tag
            || now < candidate.issued
            || now.duration_since(candidate.issued) > Duration::from_secs(60)
        {
            return Ok(false);
        }
        let candidate = *self.pending_restart.take().unwrap();
        let previous_tag = self.my_verification_tag;
        let mut replacement = Association::new(
            Some(Arc::new(ServerConfig::new(
                (*self.transport_config).clone(),
            ))),
            self.transport_config.clone(),
            self.max_payload_size,
            candidate.local_tag,
            self.remote_addr,
            self.local_addr,
            self.transport_protocol,
            now,
        );
        replacement.side = self.side;
        replacement.my_next_tsn = candidate.local_tsn;
        replacement.my_next_rsn = candidate.local_tsn;
        replacement.min_tsn2measure_rtt = candidate.local_tsn;
        replacement.cumulative_tsn_ack_point = candidate.local_tsn.wrapping_sub(1);
        replacement.advanced_peer_tsn_ack_point = candidate.local_tsn.wrapping_sub(1);
        replacement.handle_init(packet, &candidate.peer_init)?;
        replacement.my_max_num_inbound_streams = self
            .my_max_num_inbound_streams
            .min(candidate.peer_init.num_outbound_streams);
        replacement.my_max_num_outbound_streams = self
            .my_max_num_outbound_streams
            .min(candidate.peer_init.num_inbound_streams);
        replacement.my_cookie = Some(candidate.cookie);
        replacement.set_state(AssociationState::Established);
        replacement.handshake_completed = true;
        replacement.restart_generation = self.restart_generation.wrapping_add(1);
        replacement.next_stream_generation = self.next_stream_generation;
        replacement.stats = std::mem::take(&mut self.stats);
        replacement.bytes_sent = self.bytes_sent;
        replacement.bytes_received = self.bytes_received;
        replacement
            .events
            .extend(self.events.drain(..).filter(|event| {
                matches!(
                    event,
                    Event::Stream(StreamEvent::BufferedAmountReleased { .. })
                )
            }));
        for (id, mut stream) in std::mem::take(&mut self.streams) {
            if stream.buffered_amount != 0 {
                replacement
                    .events
                    .push_back(Event::Stream(StreamEvent::BufferedAmountReleased {
                        id,
                        n_bytes: stream.buffered_amount,
                    }));
            }
            if stream.state != RecvSendState::ReadWritable
                || id >= replacement.my_max_num_inbound_streams
                || id >= replacement.my_max_num_outbound_streams
            {
                replacement
                    .events
                    .push_back(Event::Stream(StreamEvent::Stopped {
                        id,
                        error_code: crate::chunk::INVALID_STREAM_IDENTIFIER,
                    }));
                continue;
            }
            stream.reassembly_queue = ReassemblyQueue::new(id);
            stream.sequence_number = 0;
            stream.buffered_amount = 0;
            stream.generation = replacement.next_stream_generation;
            replacement.next_stream_generation = replacement.next_stream_generation.wrapping_add(1);
            replacement.streams.insert(id, stream);
        }
        replacement
            .endpoint_events
            .push_back(EndpointEventInner::AssociationIdChanged {
                previous: previous_tag,
                current: candidate.local_tag,
            });
        replacement.events.push_back(Event::Connected);
        *self = replacement;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates an established association and a fresh restart cookie using caller time.
    fn proposed_restart(now: Instant) -> (Association, Packet, ChunkCookieEcho) {
        let config = Arc::new(TransportConfig::default());
        let mut association = Association::new(
            Some(Arc::new(ServerConfig::new((*config).clone()))),
            config,
            1400,
            10,
            "127.0.0.1:40001".parse().unwrap(),
            "127.0.0.1:40000".parse().unwrap(),
            TransportProtocol::UDP,
            now,
        );
        association.set_state(AssociationState::Established);
        association.handshake_completed = true;
        association.peer_verification_tag = 20;
        association.my_max_num_inbound_streams = 10;
        association.my_max_num_outbound_streams = 10;
        association.source_port = 5000;
        association.destination_port = 5000;
        let packet = Packet {
            common_header: CommonHeader {
                source_port: 5000,
                destination_port: 5000,
                verification_tag: 0,
            },
            chunks: vec![],
        };
        let init = ChunkInit {
            initiate_tag: 30,
            initial_tsn: 100,
            num_inbound_streams: 10,
            num_outbound_streams: 10,
            advertised_receiver_window_credit: 65536,
            ..Default::default()
        };
        association
            .handle_restart_init(&packet, &init, now)
            .unwrap();
        assert_eq!(association.my_verification_tag, 10);
        assert_eq!(association.peer_verification_tag, 20);
        let candidate = association.pending_restart.as_ref().unwrap();
        let echo = ChunkCookieEcho {
            cookie: candidate.cookie.cookie.clone(),
        };
        let packet = Packet {
            common_header: CommonHeader {
                verification_tag: candidate.local_tag,
                ..packet.common_header
            },
            chunks: vec![],
        };
        (association, packet, echo)
    }

    #[test]
    fn restart_cookies_reject_tampering_wrong_tags_tuples_expiry_and_stale_generations() {
        let now = Instant::now();
        for invalid in 0..6 {
            let (mut association, mut packet, mut echo) = proposed_restart(now);
            let mut received_at = now;
            match invalid {
                0 => {
                    let mut bytes = echo.cookie.to_vec();
                    bytes[0] ^= 1;
                    echo.cookie = bytes.into();
                }
                1 => packet.common_header.verification_tag ^= 1,
                2 => packet.common_header.source_port += 1,
                3 => received_at += Duration::from_secs(61),
                4 => received_at -= Duration::from_nanos(1),
                _ => association.peer_verification_tag += 1,
            }
            assert!(
                !association
                    .accept_restart_cookie(&packet, &echo, received_at)
                    .unwrap()
            );
            assert_eq!(association.my_verification_tag, 10);
        }
        let (mut association, packet, echo) = proposed_restart(now);
        assert!(
            association
                .accept_restart_cookie(&packet, &echo, now)
                .unwrap()
        );
        let tag = association.my_verification_tag;
        assert!(
            !association
                .accept_restart_cookie(&packet, &echo, now)
                .unwrap()
        );
        assert_eq!(association.my_verification_tag, tag);
        let stale = Packet {
            common_header: CommonHeader {
                verification_tag: 10,
                ..packet.common_header
            },
            chunks: vec![Box::new(echo)],
        };
        association.handle_inbound(stale, now).unwrap();
        assert!(
            association.control_queue.is_empty(),
            "old-tag cookie must not trigger an ACK"
        );
    }

    #[test]
    fn duplicate_restart_proposal_keeps_the_first_cookie_valid() {
        let now = Instant::now();
        let (mut association, packet, echo) = proposed_restart(now);
        let init = association
            .pending_restart
            .as_ref()
            .unwrap()
            .peer_init
            .clone();
        let init_packet = Packet {
            common_header: CommonHeader {
                verification_tag: 0,
                ..packet.common_header
            },
            chunks: vec![],
        };
        association
            .handle_restart_init(&init_packet, &init, now + Duration::from_secs(1))
            .unwrap();
        assert!(
            association
                .accept_restart_cookie(&packet, &echo, now + Duration::from_secs(2))
                .unwrap()
        );
        assert!(
            !association
                .accept_restart_cookie(&packet, &echo, now + Duration::from_secs(2))
                .unwrap()
        );
    }

    #[test]
    fn restart_releases_all_buffers_and_preserves_unpolled_accounting() {
        let now = Instant::now();
        let (mut association, packet, echo) = proposed_restart(now);
        association
            .open_stream(0, PayloadProtocolIdentifier::Binary)
            .unwrap()
            .write(now, b"ackretained")
            .unwrap();
        association
            .open_stream(9, PayloadProtocolIdentifier::Binary)
            .unwrap()
            .write(now, b"removed")
            .unwrap();
        association
            .open_stream(8, PayloadProtocolIdentifier::Binary)
            .unwrap()
            .write(now, b"closing")
            .unwrap();
        association.streams.get_mut(&8).unwrap().state = RecvSendState::Readable;
        let mut acknowledged = FxHashMap::default();
        acknowledged.insert(0, 3);
        association.release_stream_buffers(&acknowledged);
        let init = &mut association.pending_restart.as_mut().unwrap().peer_init;
        init.num_inbound_streams = 1;
        init.num_outbound_streams = 1;
        assert!(
            association
                .accept_restart_cookie(&packet, &echo, now)
                .unwrap()
        );
        let releases: usize = std::iter::from_fn(|| association.poll())
            .filter_map(|event| match event {
                Event::Stream(StreamEvent::BufferedAmountReleased { n_bytes, .. }) => Some(n_bytes),
                _ => None,
            })
            .sum();
        assert_eq!(releases, 3 + 8 + 7 + 7);
        assert_eq!(association.buffered_amount(), 0);
        assert!(association.stream(0).unwrap().is_writable());
        assert!(association.stream(9).is_err());
        assert!(association.stream(8).is_err());
    }
}
