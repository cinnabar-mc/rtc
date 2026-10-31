use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use std::time::Instant;

/// Data-channel SDP advertises its single transport component without a separate RTCP path.
#[test]
fn data_channel_sdp_advertises_one_ice_component() -> anyhow::Result<()> {
    let now = Instant::now();
    let mut peer = RTCPeerConnectionBuilder::new().build(now)?;
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".into(),
            address: "127.0.0.1".into(),
            port: 40000,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    peer.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;
    peer.create_data_channel("fixture", None)?;
    let offer = peer.create_offer(None)?;
    peer.set_local_description(now, offer.clone())?;
    for description in [offer, peer.local_description().unwrap()] {
        let candidates: Vec<_> = description
            .sdp
            .lines()
            .filter_map(|line| line.strip_prefix("a=candidate:"))
            .collect();
        assert_eq!(candidates.len(), 1, "data channels have one ICE component");
        assert_eq!(candidates[0].split_whitespace().nth(1), Some("1"));
    }
    Ok(())
}
