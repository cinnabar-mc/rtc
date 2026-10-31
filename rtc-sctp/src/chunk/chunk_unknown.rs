use super::*;

/// An unrecognized wire chunk retained for action-bit processing and error reports.
#[derive(Debug)]
pub(crate) struct ChunkUnknown {
    pub(crate) raw: Bytes,
}

impl fmt::Display for ChunkUnknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.header())
    }
}

impl Chunk for ChunkUnknown {
    fn header(&self) -> ChunkHeader {
        ChunkHeader {
            typ: chunk_type::ChunkType(self.raw[0]),
            flags: self.raw[1],
            value_length: self.value_length() as u16,
        }
    }
    fn unmarshal(raw: &Bytes) -> Result<Self> {
        let header = ChunkHeader::unmarshal(raw)?;
        Ok(Self {
            raw: raw.slice(..CHUNK_HEADER_SIZE + header.value_length()),
        })
    }
    fn marshal_to(&self, buf: &mut BytesMut) -> Result<usize> {
        buf.extend_from_slice(&self.raw);
        Ok(buf.len())
    }
    fn check(&self) -> Result<()> {
        Ok(())
    }
    fn value_length(&self) -> usize {
        self.raw.len() - CHUNK_HEADER_SIZE
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
