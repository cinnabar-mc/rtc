#[cfg(test)]
mod fragment_buffer_test;

use crate::content::*;
use crate::handshake::handshake_header::*;
use crate::record_layer::record_layer_header::*;
use shared::error::*;

use std::collections::HashMap;
use std::io::{BufWriter, Cursor};

// Preserve the 2 MB payload budget and separately bound retained fragment metadata.
const FRAGMENT_BUFFER_MAX_SIZE: usize = 2_000_000;
const FRAGMENT_BUFFER_MAX_RETAINED_SIZE: usize = 2 * FRAGMENT_BUFFER_MAX_SIZE;

pub(crate) struct Fragment {
    record_layer_header: RecordLayerHeader,
    handshake_header: HandshakeHeader,
    data: Vec<u8>,
}

pub(crate) struct FragmentBuffer {
    // map of MessageSequenceNumbers that hold slices of fragments
    cache: HashMap<u16, Vec<Fragment>>,

    current_message_sequence_number: u32,
}

impl FragmentBuffer {
    pub fn new() -> Self {
        FragmentBuffer {
            cache: HashMap::new(),
            current_message_sequence_number: 0,
        }
    }

    // Attempts to push a DTLS packet to the FragmentBuffer
    // when it returns true it means the FragmentBuffer has inserted and the buffer shouldn't be handled
    // when an error returns it is fatal, and the DTLS connection should be stopped
    pub fn push(&mut self, mut buf: &[u8]) -> Result<bool> {
        let mut reader = Cursor::new(buf);
        let record_layer_header = RecordLayerHeader::unmarshal(&mut reader)?;

        // Fragment isn't a handshake, we don't need to handle it
        if record_layer_header.content_type != ContentType::Handshake {
            return Ok(false);
        }

        buf = &buf[RECORD_LAYER_HEADER_SIZE..];
        while !buf.is_empty() {
            let mut reader = Cursor::new(buf);
            let handshake_header = HandshakeHeader::unmarshal(&mut reader)?;

            let end = HANDSHAKE_HEADER_LENGTH + handshake_header.fragment_length as usize;
            let offset = handshake_header.fragment_offset as usize;
            let length = handshake_header.length as usize;
            if end > buf.len() || offset + handshake_header.fragment_length as usize > length {
                return Err(Error::ErrLengthMismatch);
            }
            let data = &buf[HANDSHAKE_HEADER_LENGTH..end];
            let sequence = handshake_header.message_sequence;
            if (sequence as u32) < self.current_message_sequence_number
                || (data.is_empty() && length != 0)
            {
                buf = &buf[end..];
                continue;
            }
            if let Some(fragments) = self.cache.get(&sequence) {
                let mut redundant = false;
                for fragment in fragments {
                    if fragment.handshake_header.length != handshake_header.length
                        || fragment.handshake_header.handshake_type
                            != handshake_header.handshake_type
                        || fragment.record_layer_header.epoch != record_layer_header.epoch
                    {
                        return Err(Error::ErrLengthMismatch);
                    }
                    let start = fragment.handshake_header.fragment_offset as usize;
                    let overlap_start = start.max(offset);
                    let overlap_end = (start + fragment.data.len()).min(offset + data.len());
                    if overlap_start < overlap_end
                        && fragment.data[overlap_start - start..overlap_end - start]
                            != data[overlap_start - offset..overlap_end - offset]
                    {
                        return Err(Error::ErrLengthMismatch);
                    }
                    if start <= offset && start + fragment.data.len() >= offset + data.len() {
                        // This range is already retained, including repeated empty messages.
                        redundant = true;
                        break;
                    }
                }
                if redundant {
                    buf = &buf[end..];
                    continue;
                }
            }
            let (payload_size, retained_size) = self.sizes();
            let new_size = retained_size + data.len() + std::mem::size_of::<Fragment>();
            let new_payload_size = payload_size + data.len();
            if new_payload_size > FRAGMENT_BUFFER_MAX_SIZE
                || new_size > FRAGMENT_BUFFER_MAX_RETAINED_SIZE
            {
                return Err(Error::ErrFragmentBufferOverflow {
                    new_size,
                    max_size: FRAGMENT_BUFFER_MAX_RETAINED_SIZE,
                });
            }
            let fragments = self.cache.entry(sequence).or_default();
            fragments.push(Fragment {
                record_layer_header,
                handshake_header,
                data: data.to_vec(),
            });
            fragments.sort_unstable_by_key(|fragment| fragment.handshake_header.fragment_offset);
            buf = &buf[end..];
        }

        Ok(true)
    }

    pub fn pop(&mut self) -> Result<(Vec<u8>, u16)> {
        let seq_num = u16::try_from(self.current_message_sequence_number)
            .map_err(|_| Error::ErrEmptyFragment)?;
        if !self.cache.contains_key(&seq_num) {
            return Err(Error::ErrEmptyFragment);
        }

        let (content, epoch) = if let Some(frags) = self.cache.get_mut(&seq_num) {
            let mut raw_message = vec![];
            for fragment in frags.iter() {
                let offset = fragment.handshake_header.fragment_offset as usize;
                if offset > raw_message.len() {
                    return Err(Error::ErrEmptyFragment);
                }
                let skip = raw_message
                    .len()
                    .saturating_sub(offset)
                    .min(fragment.data.len());
                raw_message.extend_from_slice(&fragment.data[skip..]);
            }
            if raw_message.len() != frags[0].handshake_header.length as usize {
                return Err(Error::ErrEmptyFragment);
            }

            let mut first_header = frags[0].handshake_header;
            first_header.fragment_offset = 0;
            first_header.fragment_length = first_header.length;

            let mut raw_header = vec![];
            {
                let mut writer = BufWriter::<&mut Vec<u8>>::new(raw_header.as_mut());
                if first_header.marshal(&mut writer).is_err() {
                    return Err(Error::ErrEmptyFragment);
                }
            }

            let message_epoch = frags[0].record_layer_header.epoch;

            raw_header.extend_from_slice(&raw_message);

            (raw_header, message_epoch)
        } else {
            return Err(Error::ErrEmptyFragment);
        };

        self.cache.remove(&seq_num);
        self.current_message_sequence_number += 1;

        Ok((content, epoch))
    }

    /// Reports whether no retained handshake fragments remain.
    pub(crate) fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Counts payload bytes and retained fragment storage separately.
    fn sizes(&self) -> (usize, usize) {
        self.cache
            .values()
            .flatten()
            .fold((0, 0), |(payload, retained), fragment| {
                (
                    payload + fragment.data.len(),
                    retained + fragment.data.len() + std::mem::size_of::<Fragment>(),
                )
            })
    }

    #[cfg(test)]
    fn size(&self) -> usize {
        self.sizes().1
    }
}
