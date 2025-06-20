use std::collections::HashMap;
use crate::{build_frames, CMD_CBOR, CMD_INIT, REPORT_LEN};
use crate::cbor::handle_cbor_msg;
pub struct Engine {
    pub assigned_cid: u32,
    rx_state: HashMap<u32, RxBuf>,
}
struct RxBuf {
    cmd: u8,
    expected: usize,
    buf: Vec<u8>,
    next_seq: u8,
}
impl Engine {
    pub fn new() -> Self {
        Self { assigned_cid: 0, rx_state: HashMap::new() }
    }
    pub fn process_frame(&mut self, frame: [u8; REPORT_LEN]) -> Vec<[u8; REPORT_LEN]> {
        let cid = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        let cmd_byte = frame[4];
        let mut responses = Vec::new();
        if cmd_byte & 0x80 != 0 {
            let cmd = cmd_byte & 0x7F;
            let len = u16::from_be_bytes([frame[5], frame[6]]) as usize;
            let data = &frame[7..7 + len.min(57)];
            if cmd == CMD_INIT {
            }
            if len <= 57 {
                responses.extend(self.handle_msg(cid, cmd, data.to_vec()));
            } else {
                self.rx_state.insert(cid, RxBuf{ cmd, expected: len, buf: data.to_vec(), next_seq:0 });
            }
        } else {
            if let Some(state) = self.rx_state.get_mut(&cid) {
                let seq = cmd_byte;
                if seq == state.next_seq {
                    let remaining = state.expected - state.buf.len();
                    let take = remaining.min(59);
                    state.buf.extend_from_slice(&frame[5..5+take]);
                    state.next_seq +=1;
                    if state.buf.len() == state.expected {
                        let state = self.rx_state.remove(&cid).unwrap();
                        responses.extend(self.handle_msg(cid, state.cmd, state.buf));
                    }
                }
            }
        }
        responses
    }
    fn handle_msg(&mut self, cid: u32, cmd: u8, data: Vec<u8>) -> Vec<[u8; REPORT_LEN]> {
        if cmd == CMD_CBOR {
            let mut payloads = handle_cbor_msg(&data);
            let mut frames_all = Vec::new();
            for p in payloads.drain(..) {
                frames_all.extend(build_frames(cid, CMD_CBOR | 0x80, &p));
            }
            frames_all
        } else {
            Vec::new()
        }
    }
}