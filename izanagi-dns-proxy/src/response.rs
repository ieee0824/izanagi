use std::net::Ipv4Addr;

#[cfg(test)]
use hickory_proto::op::MessageType;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};

/// ブロックされたドメインに対するダミー A レコード応答を構築する。
/// クエリが A レコード以外（AAAA, MX 等）の場合は NODATA（空回答）を返す。
pub fn build_blocked_response(query: &Message, dummy_ip: Ipv4Addr) -> Message {
    let mut resp = Message::response(query.id, query.op_code);
    resp.metadata.recursion_desired = query.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::NoError;

    // クエリの Question セクションをコピー
    for q in &query.queries {
        resp.add_query(q.clone());
    }

    // A レコードのクエリにのみダミー IP で応答する
    if let Some(q) = query.queries.first()
        && q.query_type() == RecordType::A
    {
        let record = Record::from_rdata(
            q.name().clone(),
            60, // TTL 60秒
            RData::A(A(dummy_ip)),
        );
        resp.add_answer(record);
        // AAAA, MX, TXT 等は NODATA（空の Answer セクション）
    }

    resp
}

/// 上流 DNS の失敗時に返す SERVFAIL 応答を構築する。
pub fn build_servfail_response(query: &Message) -> Message {
    let mut resp = Message::response(query.id, query.op_code);
    resp.metadata.recursion_desired = query.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::ServFail;

    for q in &query.queries {
        resp.add_query(q.clone());
    }

    resp
}

/// FORMERR 応答を構築する（パースできないクエリ用）。
pub fn build_formerr_response(id: u16) -> Message {
    Message::error_msg(id, OpCode::Query, ResponseCode::FormErr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::{DNSClass, Name};

    fn make_query(name: &str, qtype: RecordType) -> Message {
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;

        let mut q = Query::new();
        q.set_name(Name::from_ascii(name).unwrap());
        q.set_query_type(qtype);
        q.set_query_class(DNSClass::IN);
        msg.add_query(q);

        msg
    }

    #[test]
    fn blocked_a_query_returns_dummy_ip() {
        let query = make_query("evil.example.com", RecordType::A);
        let resp = build_blocked_response(&query, Ipv4Addr::new(127, 0, 0, 1));

        assert_eq!(resp.id, 0x1234);
        assert_eq!(resp.message_type, MessageType::Response);
        assert_eq!(resp.response_code, ResponseCode::NoError);
        assert!(resp.recursion_available);
        assert_eq!(resp.queries.len(), 1);
        assert_eq!(resp.answers.len(), 1);

        let answer = &resp.answers[0];
        assert_eq!(&answer.name, &Name::from_ascii("evil.example.com").unwrap());
        assert_eq!(answer.ttl, 60);
        assert_eq!(&answer.data, &RData::A(A(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn blocked_aaaa_query_returns_nodata() {
        let query = make_query("evil.example.com", RecordType::AAAA);
        let resp = build_blocked_response(&query, Ipv4Addr::new(127, 0, 0, 1));

        assert_eq!(resp.response_code, ResponseCode::NoError);
        assert!(resp.answers.is_empty());
    }

    #[test]
    fn servfail_preserves_query() {
        let query = make_query("example.com", RecordType::A);
        let resp = build_servfail_response(&query);

        assert_eq!(resp.id, 0x1234);
        assert_eq!(resp.response_code, ResponseCode::ServFail);
        assert_eq!(resp.queries.len(), 1);
        assert!(resp.answers.is_empty());
    }

    #[test]
    fn formerr_response() {
        let resp = build_formerr_response(0xABCD);
        assert_eq!(resp.id, 0xABCD);
        assert_eq!(resp.response_code, ResponseCode::FormErr);
    }
}
