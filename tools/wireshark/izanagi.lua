-- izanagi.lua — Wireshark Lua dissector for the izanagi host-agent protocol.
--
-- Wire format (plain):
--   +--------+----------+------------------+
--   | type   | length   | body             |
--   | (u8)   | (u32 LE) | (bincode bytes)  |
--   +--------+----------+------------------+
--
-- Wire format (HMAC-authenticated):
--   +--------+----------+------------------+----------+--------+
--   | type   | length   | body             | sequence | hmac   |
--   | (u8)   | (u32 LE) | (bincode bytes)  | (u64 LE) | (32B)  |
--   +--------+----------+------------------+----------+--------+
--
-- Transport: TCP (default port 9001)
-- Body is bincode-serialized; this dissector does not decode bincode internals
-- but shows the raw body bytes and basic header information.

local izanagi_proto = Proto("izanagi", "Izanagi Host-Agent Protocol")

-- Preferences
izanagi_proto.prefs.hmac_mode = Pref.bool("HMAC mode",
    false,
    "Enable to parse HMAC-authenticated frames (adds sequence + HMAC fields)")

-- Header fields
local f_msg_type   = ProtoField.uint8("izanagi.type", "Message Type", base.DEC)
local f_body_len   = ProtoField.uint32("izanagi.length", "Body Length", base.DEC)
local f_body       = ProtoField.bytes("izanagi.body", "Body (bincode)")
local f_sequence   = ProtoField.uint64("izanagi.sequence", "Sequence Number", base.DEC)
local f_hmac       = ProtoField.bytes("izanagi.hmac", "HMAC-SHA256")

izanagi_proto.fields = { f_msg_type, f_body_len, f_body, f_sequence, f_hmac }

-- Message type names
local msg_type_names = {
    [0]  = "Start",
    [1]  = "Stop",
    [2]  = "Event",
    [3]  = "Ready",
    [4]  = "Error",
    [5]  = "Hello",
    [6]  = "Exec",
    [7]  = "ExecResult",
    [8]  = "Shell",
    [9]  = "ShellData",
    [10] = "ShellClose",
    [11] = "ShellResize",
}

local HEADER_SIZE = 5   -- type (1) + length (4)
local HMAC_SIZE   = 32
local SEQ_SIZE    = 8
local MAX_BODY_SIZE = 1024 * 1024  -- 1 MiB

-- Helper: human-readable message type
local function type_name(t)
    return msg_type_names[t] or string.format("Unknown(%d)", t)
end

-- Dissect a single izanagi frame starting at `offset` in `tvbuf`.
-- Returns the number of bytes consumed, or a negative number indicating
-- how many more bytes are needed (Wireshark reassembly convention).
local function dissect_one(tvbuf, pinfo, tree, offset)
    local remaining = tvbuf:len() - offset

    -- Need at least the header to determine frame length
    if remaining < HEADER_SIZE then
        return -(HEADER_SIZE - remaining)
    end

    local msg_type = tvbuf(offset, 1):le_uint()

    -- Reject unknown message types early to avoid misinterpreting random data
    if msg_type_names[msg_type] == nil then
        return 0  -- not our protocol or corrupt
    end

    local body_len = tvbuf(offset + 1, 4):le_uint()

    -- Sanity check
    if body_len > MAX_BODY_SIZE then
        return 0  -- not our protocol or corrupt
    end

    local hmac_mode = izanagi_proto.prefs.hmac_mode
    local trailer_size = 0
    if hmac_mode then
        trailer_size = SEQ_SIZE + HMAC_SIZE  -- 40 bytes
    end

    local frame_len = HEADER_SIZE + body_len + trailer_size

    -- Not enough data yet — ask Wireshark for reassembly
    if remaining < frame_len then
        return -(frame_len - remaining)
    end

    -- Build protocol tree
    local subtree = tree:add(izanagi_proto, tvbuf(offset, frame_len))
    subtree:set_text("Izanagi Protocol, " .. type_name(msg_type))

    subtree:add_le(f_msg_type, tvbuf(offset, 1))
           :append_text(" (" .. type_name(msg_type) .. ")")
    subtree:add_le(f_body_len, tvbuf(offset + 1, 4))

    if body_len > 0 then
        subtree:add(f_body, tvbuf(offset + HEADER_SIZE, body_len))
    end

    if hmac_mode then
        local seq_offset = offset + HEADER_SIZE + body_len
        subtree:add_le(f_sequence, tvbuf(seq_offset, SEQ_SIZE))
        subtree:add(f_hmac, tvbuf(seq_offset + SEQ_SIZE, HMAC_SIZE))
    end

    -- Info column
    pinfo.cols.protocol = "Izanagi"
    local info = type_name(msg_type) .. " len=" .. body_len
    if hmac_mode then
        local seq = tvbuf(offset + HEADER_SIZE + body_len, SEQ_SIZE):le_uint64()
        info = info .. " seq=" .. tostring(seq)
    end
    -- Append rather than overwrite when multiple messages per segment
    if (tostring(pinfo.cols.info) or ""):find("^Izanagi") then
        pinfo.cols.info:append(", " .. info)
    else
        pinfo.cols.info = "Izanagi: " .. info
    end

    return frame_len
end

-- Main dissector entry point — handles TCP reassembly
function izanagi_proto.dissector(tvbuf, pinfo, tree)
    local offset = 0
    local tvbuf_len = tvbuf:len()

    while offset < tvbuf_len do
        local consumed = dissect_one(tvbuf, pinfo, tree, offset)
        if consumed > 0 then
            offset = offset + consumed
        elseif consumed == 0 then
            -- Not our protocol
            return 0
        else
            -- Need more data — tell Wireshark
            pinfo.desegment_offset = offset
            pinfo.desegment_len = -consumed
            return tvbuf_len
        end
    end

    return offset
end

-- Register on the default agent port
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(9001, izanagi_proto)
