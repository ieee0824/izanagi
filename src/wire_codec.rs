//! Shared, bounded postcard codec. The framing layer owns protocol versioning.
use serde::{Serialize, de::DeserializeOwned};

pub(crate) const MAX_BODY_SIZE: usize = 1024 * 1024;

struct BoundedVec(Vec<u8>);

impl postcard::ser_flavors::Flavor for BoundedVec {
    type Output = Vec<u8>;

    fn try_push(&mut self, byte: u8) -> postcard::Result<()> {
        if self.0.len() == MAX_BODY_SIZE {
            return Err(postcard::Error::SerializeBufferFull);
        }
        self.0.push(byte);
        Ok(())
    }

    fn try_extend(&mut self, bytes: &[u8]) -> postcard::Result<()> {
        if bytes.len() > MAX_BODY_SIZE - self.0.len() {
            return Err(postcard::Error::SerializeBufferFull);
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    fn finalize(self) -> postcard::Result<Self::Output> {
        Ok(self.0)
    }
}

pub(crate) fn encode<T: Serialize + ?Sized>(value: &T) -> anyhow::Result<Vec<u8>> {
    postcard::serialize_with_flavor(value, BoundedVec(Vec::new())).map_err(|error| {
        if error == postcard::Error::SerializeBufferFull {
            anyhow::anyhow!("message body too large (max {} bytes)", MAX_BODY_SIZE)
        } else {
            anyhow::anyhow!(error)
        }
    })
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> anyhow::Result<T> {
    if bytes.len() > MAX_BODY_SIZE {
        anyhow::bail!("message body too large: {} bytes", bytes.len());
    }
    // Decode from a bounded slice, not an unbounded stream. Require full consumption.
    let (value, remainder) = postcard::take_from_bytes(bytes)?;
    if !remainder.is_empty() {
        anyhow::bail!("trailing bytes in message body");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malicious_collection_lengths_fail_on_bounded_input() {
        // usize::MAX encoded as a postcard varint, followed by no elements.
        let bytes = postcard::to_stdvec(&u64::MAX).unwrap();
        assert!(decode::<Vec<String>>(&bytes).is_err());
        assert!(decode::<std::collections::HashMap<String, String>>(&bytes).is_err());
        assert!(decode::<String>(&bytes).is_err());
    }

    #[test]
    fn decoder_rejects_oversized_input_and_trailing_data() {
        assert!(decode::<u8>(&vec![0; MAX_BODY_SIZE + 1]).is_err());
        assert!(decode::<u8>(&[1, 2]).is_err());
    }
}
