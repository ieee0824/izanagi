//! Strict raw-object compatibility checks before attaching any kernel probes.
use izanagi_common::{ABI_MAGIC, ABI_SECTION, RAW_ABI_VERSION, RAW_EVENT_SIZE};

pub(crate) fn validate_object(bytes: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(
        bytes.len() >= 64 && bytes.starts_with(b"\x7fELF") && bytes[4] == 2 && bytes[5] == 1,
        "unsupported eBPF ELF format"
    );
    fn number(bytes: &[u8], start: usize, length: usize) -> anyhow::Result<usize> {
        let data = bytes
            .get(
                start
                    ..start
                        .checked_add(length)
                        .ok_or_else(|| anyhow::anyhow!("invalid ELF offset"))?,
            )
            .ok_or_else(|| anyhow::anyhow!("truncated ELF"))?;
        let mut array = [0; 8];
        array[..length].copy_from_slice(data);
        usize::try_from(u64::from_le_bytes(array)).map_err(Into::into)
    }
    let table = number(bytes, 40, 8)?;
    let size = number(bytes, 58, 2)?;
    let count = number(bytes, 60, 2)?;
    let string_index = number(bytes, 62, 2)?;
    anyhow::ensure!(
        size >= 64 && count > 0 && count < 4096 && string_index < count,
        "invalid ELF section table"
    );
    let end = table
        .checked_add(
            size.checked_mul(count)
                .ok_or_else(|| anyhow::anyhow!("invalid ELF sections"))?,
        )
        .ok_or_else(|| anyhow::anyhow!("invalid ELF sections"))?;
    anyhow::ensure!(end <= bytes.len(), "truncated ELF sections");
    let header = table + size * string_index;
    let offset = number(bytes, header + 24, 8)?;
    let length = number(bytes, header + 32, 8)?;
    let strings = bytes
        .get(
            offset
                ..offset
                    .checked_add(length)
                    .ok_or_else(|| anyhow::anyhow!("invalid ELF strings"))?,
        )
        .ok_or_else(|| anyhow::anyhow!("truncated ELF strings"))?;
    let mut metadata = None;
    for index in 0..count {
        let header = table + size * index;
        let name = number(bytes, header, 4)?;
        let name = strings
            .get(name..)
            .and_then(|s| s.split(|b| *b == 0).next())
            .ok_or_else(|| anyhow::anyhow!("invalid ELF section name"))?;
        if name == ABI_SECTION.as_bytes() {
            anyhow::ensure!(metadata.is_none(), "duplicate raw ABI section");
            let offset = number(bytes, header + 24, 8)?;
            let length = number(bytes, header + 32, 8)?;
            metadata = bytes.get(
                offset
                    ..offset
                        .checked_add(length)
                        .ok_or_else(|| anyhow::anyhow!("invalid ABI offset"))?,
            );
        }
    }
    let metadata = metadata.ok_or_else(|| {
        anyhow::anyhow!("raw ABI metadata missing; update agent and eBPF object together")
    })?;
    anyhow::ensure!(
        metadata.len() == 16 && metadata[..8] == ABI_MAGIC,
        "invalid raw ABI metadata"
    );
    let version = u32::from_le_bytes(metadata[8..12].try_into()?);
    let size = u32::from_le_bytes(metadata[12..16].try_into()?);
    anyhow::ensure!(
        version == RAW_ABI_VERSION && size as usize == RAW_EVENT_SIZE,
        "raw ABI version/size mismatch; update agent and eBPF object together"
    );
    Ok(())
}

/// Tracepoint layouts are a separate compatibility boundary from wire and raw ABI.
#[cfg(target_os = "linux")]
pub(crate) fn validate_tracepoint(
    category: &str,
    name: &str,
    fields: &[(&str, usize, usize)],
) -> anyhow::Result<()> {
    let root = [
        "/sys/kernel/tracing/events",
        "/sys/kernel/debug/tracing/events",
    ]
    .into_iter()
    .find(|root| std::path::Path::new(root).is_dir())
    .ok_or_else(|| anyhow::anyhow!("tracefs is unavailable"))?;
    let format = std::fs::read_to_string(format!("{root}/{category}/{name}/format"))?;
    for &(field, offset, size) in fields {
        let matching = format.lines().any(|line| {
            let parts: Vec<_> = line.split(';').collect();
            parts
                .first()
                .is_some_and(|definition| definition.trim_end().ends_with(&format!(" {field}")))
                && parts
                    .iter()
                    .any(|part| part.trim() == format!("offset:{offset}"))
                && parts
                    .iter()
                    .any(|part| part.trim() == format!("size:{size}"))
        });
        anyhow::ensure!(
            matching,
            "unsupported tracepoint layout {category}/{name}/{field}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn object(version: u32, size: u32) -> Vec<u8> {
        let names = b"\0.shstrtab\0.izanagi_abi\0";
        let mut object = vec![0; 64 + 3 * 64];
        object[..6].copy_from_slice(b"\x7fELF\x02\x01");
        object[40..48].copy_from_slice(&64u64.to_le_bytes());
        object[58..60].copy_from_slice(&64u16.to_le_bytes());
        object[60..62].copy_from_slice(&3u16.to_le_bytes());
        object[62..64].copy_from_slice(&1u16.to_le_bytes());
        object[128..132].copy_from_slice(&1u32.to_le_bytes());
        object[152..160].copy_from_slice(&256u64.to_le_bytes());
        object[160..168].copy_from_slice(&(names.len() as u64).to_le_bytes());
        object[192..196].copy_from_slice(&11u32.to_le_bytes());
        object[216..224].copy_from_slice(&(256u64 + names.len() as u64).to_le_bytes());
        object[224..232].copy_from_slice(&16u64.to_le_bytes());
        object.extend_from_slice(names);
        object.extend_from_slice(&ABI_MAGIC);
        object.extend_from_slice(&version.to_le_bytes());
        object.extend_from_slice(&size.to_le_bytes());
        object
    }
    #[test]
    fn rejects_legacy_and_changed_size_before_load() {
        assert!(validate_object(&object(RAW_ABI_VERSION, RAW_EVENT_SIZE as u32)).is_ok());
        assert!(validate_object(&object(0, RAW_EVENT_SIZE as u32)).is_err());
        assert!(validate_object(&object(RAW_ABI_VERSION, 344)).is_err());
        assert!(validate_object(b"legacy").is_err());
        let good = object(RAW_ABI_VERSION, RAW_EVENT_SIZE as u32);
        for length in 0..good.len() {
            assert!(validate_object(&good[..length]).is_err());
        }
    }
}
