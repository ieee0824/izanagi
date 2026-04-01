//! pcap ファイル書き込みユーティリティ。
//!
//! QEMU サンドボックスの host <-> agent 間 TCP 通信を
//! pcap 形式でファイルに記録する。
//!
//! ## フォーマット
//!
//! - Global Header: magic=0xa1b2c3d4, version=2.4, snaplen=65535
//! - Link-layer type: `LINKTYPE_USER0` (147) — アプリケーション固有ペイロード
//! - Packet Header: ts_sec, ts_usec, incl_len, orig_len
//! - Packet Data: 方向バイト (0x00=host->guest, 0x01=guest->host) + raw payload
//!
//! Wireshark の Lua dissector (`tools/wireshark/izanagi.lua`) でデコード可能。

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

/// pcap グローバルヘッダーのマジックナンバー。
const PCAP_MAGIC: u32 = 0xa1b2c3d4;
/// pcap メジャーバージョン。
const PCAP_VERSION_MAJOR: u16 = 2;
/// pcap マイナーバージョン。
const PCAP_VERSION_MINOR: u16 = 4;
/// 最大キャプチャ長。
const PCAP_SNAPLEN: u32 = 65535;
/// リンクレイヤータイプ: LINKTYPE_USER0 (アプリケーション固有)。
const LINKTYPE_USER0: u32 = 147;

/// パケットの送信方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// ホスト -> ゲスト (送信)
    HostToGuest = 0x00,
    /// ゲスト -> ホスト (受信)
    GuestToHost = 0x01,
}

/// pcap ファイルへのスレッドセーフなライター。
///
/// `Mutex` で内部状態を保護し、複数スレッドから安全に書き込み可能。
pub struct PcapWriter {
    inner: Mutex<BufWriter<File>>,
}

impl PcapWriter {
    /// 新しい pcap ファイルを作成し、グローバルヘッダーを書き込む。
    pub fn create(path: &Path) -> io::Result<Self> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        write_global_header(&mut writer)?;
        writer.flush()?;
        Ok(Self {
            inner: Mutex::new(writer),
        })
    }

    /// パケットを pcap ファイルに書き込む。
    ///
    /// `direction` バイトをペイロードの先頭に付加して記録する。
    /// タイムスタンプは現在時刻を使用する。
    pub fn write_packet(&self, direction: Direction, payload: &[u8]) -> io::Result<()> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        self.write_packet_with_timestamp(
            direction,
            payload,
            now.as_secs() as u32,
            now.subsec_micros(),
        )
    }

    /// タイムスタンプを指定してパケットを書き込む（テスト用にも使用）。
    pub fn write_packet_with_timestamp(
        &self,
        direction: Direction,
        payload: &[u8],
        ts_sec: u32,
        ts_usec: u32,
    ) -> io::Result<()> {
        // 方向バイト (1 byte) + payload
        let incl_len = (1 + payload.len()).min(PCAP_SNAPLEN as usize) as u32;
        let orig_len = (1 + payload.len()) as u32;

        let mut guard = self
            .inner
            .lock()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        // Packet Header (16 bytes)
        guard.write_all(&ts_sec.to_le_bytes())?;
        guard.write_all(&ts_usec.to_le_bytes())?;
        guard.write_all(&incl_len.to_le_bytes())?;
        guard.write_all(&orig_len.to_le_bytes())?;

        // Packet Data: direction byte + payload (snaplen でトランケート)
        guard.write_all(&[direction as u8])?;
        let payload_limit = (PCAP_SNAPLEN as usize).saturating_sub(1);
        let data = if payload.len() > payload_limit {
            &payload[..payload_limit]
        } else {
            payload
        };
        guard.write_all(data)?;
        guard.flush()?;

        Ok(())
    }
}

/// pcap グローバルヘッダー (24 bytes) を書き込む。
fn write_global_header(w: &mut impl Write) -> io::Result<()> {
    w.write_all(&PCAP_MAGIC.to_le_bytes())?;
    w.write_all(&PCAP_VERSION_MAJOR.to_le_bytes())?;
    w.write_all(&PCAP_VERSION_MINOR.to_le_bytes())?;
    w.write_all(&0i32.to_le_bytes())?; // thiszone
    w.write_all(&0u32.to_le_bytes())?; // sigfigs
    w.write_all(&PCAP_SNAPLEN.to_le_bytes())?;
    w.write_all(&LINKTYPE_USER0.to_le_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn global_header_format() {
        let dir = std::env::temp_dir().join("izanagi_pcap_test_global");
        let _ = std::fs::remove_file(&dir);

        let _writer = PcapWriter::create(&dir).unwrap();

        let data = std::fs::read(&dir).unwrap();
        assert_eq!(data.len(), 24, "Global header should be 24 bytes");

        // magic
        assert_eq!(
            u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            0xa1b2c3d4
        );
        // version major
        assert_eq!(u16::from_le_bytes([data[4], data[5]]), 2);
        // version minor
        assert_eq!(u16::from_le_bytes([data[6], data[7]]), 4);
        // thiszone
        assert_eq!(
            i32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            0
        );
        // sigfigs
        assert_eq!(
            u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            0
        );
        // snaplen
        assert_eq!(
            u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            65535
        );
        // network (LINKTYPE_USER0)
        assert_eq!(
            u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            147
        );

        std::fs::remove_file(&dir).unwrap();
    }

    #[test]
    fn write_single_packet() {
        let path = std::env::temp_dir().join("izanagi_pcap_test_packet");
        let _ = std::fs::remove_file(&path);

        let writer = PcapWriter::create(&path).unwrap();

        let payload = b"hello";
        writer
            .write_packet_with_timestamp(Direction::HostToGuest, payload, 1000, 500)
            .unwrap();

        let mut data = Vec::new();
        File::open(&path).unwrap().read_to_end(&mut data).unwrap();

        // Global header (24) + Packet header (16) + direction (1) + payload (5)
        assert_eq!(data.len(), 24 + 16 + 1 + 5);

        let pkt = &data[24..];

        // ts_sec
        assert_eq!(u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]), 1000);
        // ts_usec
        assert_eq!(u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]), 500);
        // incl_len = 1 (direction) + 5 (payload) = 6
        assert_eq!(u32::from_le_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]), 6);
        // orig_len = 6
        assert_eq!(u32::from_le_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]), 6);
        // direction byte
        assert_eq!(pkt[16], 0x00);
        // payload
        assert_eq!(&pkt[17..22], b"hello");

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn write_multiple_packets_both_directions() {
        let path = std::env::temp_dir().join("izanagi_pcap_test_multi");
        let _ = std::fs::remove_file(&path);

        let writer = PcapWriter::create(&path).unwrap();
        writer
            .write_packet_with_timestamp(Direction::HostToGuest, b"req", 100, 0)
            .unwrap();
        writer
            .write_packet_with_timestamp(Direction::GuestToHost, b"res", 101, 0)
            .unwrap();

        let mut data = Vec::new();
        File::open(&path).unwrap().read_to_end(&mut data).unwrap();

        // 24 + (16+1+3) + (16+1+3) = 24 + 20 + 20 = 64
        assert_eq!(data.len(), 64);

        // First packet: direction = 0x00
        assert_eq!(data[24 + 16], 0x00);
        assert_eq!(&data[24 + 17..24 + 20], b"req");

        // Second packet: direction = 0x01
        assert_eq!(data[44 + 16], 0x01);
        assert_eq!(&data[44 + 17..44 + 20], b"res");

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn write_empty_payload() {
        let path = std::env::temp_dir().join("izanagi_pcap_test_empty");
        let _ = std::fs::remove_file(&path);

        let writer = PcapWriter::create(&path).unwrap();
        writer
            .write_packet_with_timestamp(Direction::HostToGuest, b"", 0, 0)
            .unwrap();

        let mut data = Vec::new();
        File::open(&path).unwrap().read_to_end(&mut data).unwrap();

        // 24 + 16 + 1 (direction only, no payload)
        assert_eq!(data.len(), 41);

        let pkt = &data[24..];
        // incl_len = 1
        assert_eq!(u32::from_le_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]), 1);
        // direction byte
        assert_eq!(pkt[16], 0x00);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn thread_safety() {
        let path = std::env::temp_dir().join("izanagi_pcap_test_threads");
        let _ = std::fs::remove_file(&path);

        let writer = std::sync::Arc::new(PcapWriter::create(&path).unwrap());
        let mut handles = Vec::new();

        for i in 0..10u8 {
            let w = writer.clone();
            handles.push(std::thread::spawn(move || {
                w.write_packet_with_timestamp(Direction::HostToGuest, &[i], i as u32, 0)
                    .unwrap();
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let data = std::fs::read(&path).unwrap();
        // 24 + 10 * (16 + 1 + 1) = 24 + 180 = 204
        assert_eq!(data.len(), 204);

        std::fs::remove_file(&path).unwrap();
    }
}
