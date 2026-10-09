//! Validate the few kernel field offsets used by writer probes from running BTF.
//! No guessed kernel layout. Encoding: https://docs.kernel.org/bpf/btf.html
use anyhow::{Result, bail, ensure};

#[cfg(target_os = "linux")]
pub(super) fn load() -> Result<[u32; 4]> {
    let bytes = std::fs::read("/sys/kernel/btf/vmlinux")?;
    offsets(&bytes)
}

fn offsets(bytes: &[u8]) -> Result<[u32; 4]> {
    let btf = Btf::parse(bytes)?;
    btf.sendmsg_signature()?;
    let seq = btf.field("tcp_sock", &["write_seq"], 4, 1)?;
    let net = btf.field("sock", &["__sk_common", "skc_net", "net"], 8, 2)?;
    let inum = btf.field("net", &["ns", "inum"], 4, 1)?;
    Ok([seq, net, inum, 1])
}

struct Type<'a> {
    name: u32,
    info: u32,
    value: u32,
    extra: &'a [u8],
}
impl Type<'_> {
    fn kind(&self) -> u32 {
        (self.info >> 24) & 31
    }
}
struct Btf<'a> {
    types: Vec<Type<'a>>,
    strings: &'a [u8],
}
impl<'a> Btf<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= 32 * 1024 * 1024 && bytes.get(..4) == Some(&[0x9f, 0xeb, 1, 0]),
            "unsupported kernel BTF"
        );
        let header = word(bytes, 4)? as usize;
        ensure!(header >= 24 && header <= bytes.len(), "invalid BTF header");
        let section = |offset, length| -> Result<&'a [u8]> {
            let start = header
                .checked_add(word(bytes, offset)? as usize)
                .ok_or_else(|| anyhow::anyhow!("BTF overflow"))?;
            let end = start
                .checked_add(word(bytes, length)? as usize)
                .ok_or_else(|| anyhow::anyhow!("BTF overflow"))?;
            bytes
                .get(start..end)
                .ok_or_else(|| anyhow::anyhow!("truncated BTF section"))
        };
        let mut data = section(8, 12)?;
        let strings = section(16, 20)?;
        ensure!(strings.first() == Some(&0), "invalid BTF strings");
        let mut types = Vec::new();
        while !data.is_empty() {
            ensure!(types.len() < 262144, "too many BTF types");
            let info = word(data, 4)?;
            let size = extra_size(info)?;
            let extra = data
                .get(12..12 + size)
                .ok_or_else(|| anyhow::anyhow!("truncated BTF type"))?;
            types.push(Type {
                name: word(data, 0)?,
                info,
                value: word(data, 8)?,
                extra,
            });
            data = &data[12 + size..];
        }
        Ok(Self { types, strings })
    }

    fn name(&self, offset: u32) -> Result<&str> {
        let data = self
            .strings
            .get(offset as usize..)
            .ok_or_else(|| anyhow::anyhow!("invalid BTF string offset"))?;
        let end = data
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| anyhow::anyhow!("unterminated BTF name"))?;
        Ok(std::str::from_utf8(&data[..end])?)
    }

    fn resolve(&self, mut id: u32) -> Result<&Type<'a>> {
        for _ in 0..16 {
            let ty = self
                .types
                .get(
                    id.checked_sub(1)
                        .ok_or_else(|| anyhow::anyhow!("void BTF field"))?
                        as usize,
                )
                .ok_or_else(|| anyhow::anyhow!("invalid BTF type ID"))?;
            if !matches!(ty.kind(), 8..=11 | 18) {
                return Ok(ty);
            }
            id = ty.value;
        }
        bail!("cyclic BTF type")
    }

    fn field(&self, root: &str, path: &[&str], width: u32, kind: u32) -> Result<u32> {
        let parent = self.named(root, 4)?;
        let mut ty = parent;
        let mut total = 0u32;
        for name in path {
            let (child, offset) = self.member(ty, name)?;
            total = total
                .checked_add(offset)
                .ok_or_else(|| anyhow::anyhow!("BTF offset overflow"))?;
            ty = child;
        }
        ensure!(ty.kind() == kind, "unexpected BTF field type");
        if kind == 1 {
            ensure!(
                ty.value == width && word(ty.extra, 0)? & 0xffff == width * 8,
                "unexpected BTF integer width"
            );
        } else {
            ensure!(
                kind == 2 && width == 8 && self.name(self.resolve(ty.value)?.name)? == "net",
                "unexpected BTF pointer target"
            );
        }
        ensure!(
            total
                .checked_add(width)
                .is_some_and(|end| end <= parent.value),
            "BTF field outside struct"
        );
        Ok(total)
    }

    fn named(&self, name: &str, kind: u32) -> Result<&Type<'a>> {
        let mut matches = self
            .types
            .iter()
            .filter(|t| t.kind() == kind)
            .filter(|t| self.name(t.name).is_ok_and(|n| n == name));
        let ty = matches
            .next()
            .ok_or_else(|| anyhow::anyhow!("kernel BTF name missing: {name}"))?;
        ensure!(
            matches.next().is_none(),
            "ambiguous kernel BTF name: {name}"
        );
        Ok(ty)
    }

    fn sendmsg_signature(&self) -> Result<()> {
        let func = self.named("tcp_sendmsg_locked", 12)?;
        let proto = self.resolve(func.value)?;
        ensure!(
            proto.kind() == 13 && proto.info & 0xffff == 3,
            "unsupported tcp_sendmsg_locked signature"
        );
        for (index, expected) in ["sock", "msghdr"].iter().enumerate() {
            let ptr = self.resolve(word(proto.extra, index * 8 + 4)?)?;
            ensure!(
                ptr.kind() == 2 && self.name(self.resolve(ptr.value)?.name)? == *expected,
                "unsupported sendmsg argument"
            );
        }
        let size = self.resolve(word(proto.extra, 20)?)?;
        let result = self.resolve(proto.value)?;
        ensure!(
            size.kind() == 1 && size.value == 8 && word(size.extra, 0)? & 0xffff == 64,
            "unsupported sendmsg size type"
        );
        ensure!(
            result.kind() == 1 && result.value == 4 && word(result.extra, 0)? & 0xffff == 32,
            "unsupported sendmsg return type"
        );
        Ok(())
    }

    fn member(&self, ty: &Type<'a>, name: &str) -> Result<(&Type<'a>, u32)> {
        ensure!(matches!(ty.kind(), 4 | 5), "BTF path is not a struct");
        let mut found = None;
        for member in ty.extra.as_chunks::<12>().0 {
            if self.name(word(member, 0)?)? != name {
                continue;
            }
            ensure!(found.is_none(), "duplicate BTF member");
            let bits = word(member, 8)?;
            ensure!(
                ty.info >> 31 == 0 || bits >> 24 == 0,
                "BTF bitfield unsupported"
            );
            ensure!(
                bits % 8 == 0 && bits / 8 < ty.value,
                "invalid BTF member offset"
            );
            let child = self.resolve(word(member, 4)?)?;
            let size = if child.kind() == 2 { 8 } else { child.value };
            ensure!(
                (bits / 8)
                    .checked_add(size)
                    .is_some_and(|end| end <= ty.value),
                "BTF member outside parent"
            );
            found = Some((child, bits / 8));
        }
        found.ok_or_else(|| anyhow::anyhow!("kernel BTF member missing: {name}"))
    }
}

fn extra_size(info: u32) -> Result<usize> {
    let count = (info & 0xffff) as usize;
    Ok(match (info >> 24) & 31 {
        1 | 14 | 17 => 4,
        3 => 12,
        4 | 5 | 15 | 19 => count * 12,
        6 | 13 => count * 8,
        2 | 7..=12 | 16 | 18 => 0,
        _ => bail!("unsupported BTF kind"),
    })
}
fn word(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(|| anyhow::anyhow!("truncated BTF word"))?
            .try_into()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_truncated_or_incompatible_kernel_btf_never_guesses_offsets() {
        for bytes in [vec![], vec![0; 24], minimal()] {
            assert!(offsets(&bytes).is_err());
            for length in 0..bytes.len() {
                assert!(offsets(&bytes[..length]).is_err());
            }
        }
    }
    fn minimal() -> Vec<u8> {
        let mut bytes = vec![0x9f, 0xeb, 1, 0];
        for word in [24u32, 0, 0, 0, 1] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.push(0);
        bytes
    }

    #[test]
    fn offsets_require_exact_field_widths_and_sendmsg_signature() {
        let bytes = fixture();
        assert_eq!(offsets(&bytes).unwrap(), [4, 0, 0, 1]);
        let mut wrong_width = bytes.clone();
        wrong_width[36..40].copy_from_slice(&16u32.to_le_bytes());
        assert!(offsets(&wrong_width).is_err());
        for length in 0..bytes.len() {
            assert!(offsets(&bytes[..length]).is_err());
        }
        let mut wrong_signature = Btf::parse(&bytes).unwrap();
        wrong_signature.types[13].info = 13 << 24 | 2;
        assert!(wrong_signature.sendmsg_signature().is_err());
    }

    struct Builder {
        data: Vec<u8>,
        strings: Vec<u8>,
    }
    impl Builder {
        fn name(&mut self, name: &str) -> u32 {
            let offset = self.strings.len() as u32;
            self.strings.extend_from_slice(name.as_bytes());
            self.strings.push(0);
            offset
        }
        fn ty(&mut self, name: &str, kind: u32, value: u32, extra: &[u32], count: u32) {
            let name = self.name(name);
            for value in [name, kind << 24 | count, value].iter().chain(extra) {
                self.data.extend_from_slice(&value.to_le_bytes());
            }
        }
        fn structure(&mut self, name: &str, size: u32, member: &str, id: u32, bits: u32) {
            let field = self.name(member);
            self.ty(name, 4, size, &[field, id, bits], 1);
        }
    }

    fn fixture() -> Vec<u8> {
        let mut b = Builder {
            data: Vec::new(),
            strings: vec![0],
        };
        b.ty("u32", 1, 4, &[32], 0); // ID 1
        b.ty("size_t", 1, 8, &[64], 0);
        b.ty("int", 1, 4, &[1 << 24 | 32], 0);
        b.structure("ns_common", 4, "inum", 1, 0);
        b.structure("net", 4, "ns", 4, 0);
        b.ty("", 2, 5, &[], 0);
        b.structure("possible_net_t", 8, "net", 6, 0);
        b.structure("sock_common", 8, "skc_net", 7, 0);
        b.structure("sock", 8, "__sk_common", 8, 0);
        b.structure("tcp_sock", 8, "write_seq", 1, 32);
        b.ty("", 2, 9, &[], 0);
        b.ty("msghdr", 4, 8, &[], 0);
        b.ty("", 2, 12, &[], 0);
        b.ty("", 13, 3, &[0, 11, 0, 13, 0, 2], 3);
        b.ty("tcp_sendmsg_locked", 12, 14, &[], 1);
        let mut bytes = vec![0x9f, 0xeb, 1, 0];
        for word in [
            24u32,
            0,
            b.data.len() as u32,
            b.data.len() as u32,
            b.strings.len() as u32,
        ] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend(b.data);
        bytes.extend(b.strings);
        bytes
    }
}
