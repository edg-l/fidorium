use super::{CtapHidError, types::*};
use crate::config::CHANNEL_TIMEOUT_SECS;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub enum ChannelState {
    Idle {
        last_activity: Instant,
    },
    Receiving {
        cmd: u8,
        bcnt: u16,
        data: Vec<u8>,
        next_seq: u8,
        deadline: Instant,
    },
    Processing {
        last_activity: Instant,
    },
}

pub struct Message {
    pub cid: u32,
    pub cmd: u8,
    pub payload: Vec<u8>,
}

pub struct ChannelManager {
    channels: HashMap<u32, ChannelState>,
    max_channels: usize,
    rng: StdRng,
}

impl ChannelManager {
    pub fn new(max_channels: usize) -> Self {
        Self {
            channels: HashMap::new(),
            max_channels,
            rng: StdRng::from_entropy(),
        }
    }

    pub fn allocate_cid(&mut self) -> Result<u32, CtapHidError> {
        self.reap_timed_out();
        if self.channels.len() >= self.max_channels {
            return Err(CtapHidError::ChannelBusy);
        }
        loop {
            let cid: u32 = self.rng.r#gen();
            if cid != RESERVED_CID && cid != BROADCAST_CID && !self.channels.contains_key(&cid) {
                self.channels.insert(
                    cid,
                    ChannelState::Idle {
                        last_activity: Instant::now(),
                    },
                );
                return Ok(cid);
            }
        }
    }

    pub fn get(&self, cid: u32) -> Option<&ChannelState> {
        self.channels.get(&cid)
    }

    pub fn get_mut(&mut self, cid: u32) -> Option<&mut ChannelState> {
        self.channels.get_mut(&cid)
    }

    pub fn set_idle(&mut self, cid: u32) {
        if let Some(state) = self.channels.get_mut(&cid) {
            *state = ChannelState::Idle {
                last_activity: Instant::now(),
            };
        }
    }

    pub fn remove(&mut self, cid: u32) {
        self.channels.remove(&cid);
    }

    pub fn reap_timed_out(&mut self) {
        let timeout = Duration::from_secs(CHANNEL_TIMEOUT_SECS);
        self.channels.retain(|_, state| {
            let last = match state {
                ChannelState::Idle { last_activity } => *last_activity,
                ChannelState::Receiving { deadline, .. } => return Instant::now() < *deadline,
                ChannelState::Processing { last_activity } => *last_activity,
            };
            last.elapsed() < timeout
        });
    }

    pub fn feed_init(
        &mut self,
        cid: u32,
        cmd: u8,
        bcnt: u16,
        data: Vec<u8>,
    ) -> Result<Option<Message>, CtapHidError> {
        if (bcnt as usize) > MAX_MESSAGE_SIZE {
            return Err(CtapHidError::InvalidLen(bcnt));
        }

        // Broadcast CID is stateless
        if cid == BROADCAST_CID {
            let payload = if bcnt as usize <= data.len() {
                data[..bcnt as usize].to_vec()
            } else {
                data
            };
            return Ok(Some(Message { cid, cmd, payload }));
        }

        if !self.channels.contains_key(&cid) {
            return Err(CtapHidError::InvalidChannel(cid));
        }

        if bcnt as usize <= INIT_DATA_SIZE {
            // Fits in single packet
            let payload = data[..bcnt as usize].to_vec();
            self.set_idle(cid);
            return Ok(Some(Message { cid, cmd, payload }));
        }

        // Multi-packet: start assembling
        let deadline = Instant::now() + Duration::from_secs(CHANNEL_TIMEOUT_SECS);
        self.channels.insert(
            cid,
            ChannelState::Receiving {
                cmd,
                bcnt,
                data,
                next_seq: 0,
                deadline,
            },
        );
        Ok(None)
    }

    pub fn feed_cont(
        &mut self,
        cid: u32,
        seq: u8,
        new_data: Vec<u8>,
    ) -> Result<Option<Message>, CtapHidError> {
        // Check timeout first before borrowing mutably
        let timed_out = match self.channels.get(&cid) {
            None => return Err(CtapHidError::InvalidChannel(cid)),
            Some(ChannelState::Receiving { deadline, .. }) => Instant::now() > *deadline,
            Some(_) => return Err(CtapHidError::UnexpectedCont),
        };

        if timed_out {
            self.remove(cid);
            return Err(CtapHidError::Timeout);
        }

        // Borrow mutably now
        let (cmd, bcnt, is_complete) = match self.channels.get_mut(&cid) {
            Some(ChannelState::Receiving {
                cmd,
                bcnt,
                data,
                next_seq,
                ..
            }) => {
                if seq != *next_seq {
                    return Err(CtapHidError::InvalidSeq(seq));
                }
                *next_seq += 1;
                data.extend_from_slice(&new_data);
                let complete = data.len() >= *bcnt as usize;
                (*cmd, *bcnt, complete)
            }
            _ => unreachable!(),
        };

        if is_complete {
            let payload = match self.channels.get(&cid) {
                Some(ChannelState::Receiving { data, .. }) => data[..bcnt as usize].to_vec(),
                _ => unreachable!(),
            };
            self.set_idle(cid);
            Ok(Some(Message { cid, cmd, payload }))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feed_init_rejects_oversized_bcnt() {
        let mut manager = ChannelManager::new(1);
        let cid = manager.allocate_cid().unwrap();

        let res = manager.feed_init(
            cid,
            CMD_CBOR,
            (MAX_MESSAGE_SIZE as u16) + 1,
            vec![0u8; INIT_DATA_SIZE],
        );

        assert!(matches!(res, Err(CtapHidError::InvalidLen(_))));
    }

    #[test]
    fn test_feed_init_accepts_max_sized_bcnt() {
        let mut manager = ChannelManager::new(1);
        let cid = manager.allocate_cid().unwrap();

        let res = manager.feed_init(
            cid,
            CMD_CBOR,
            MAX_MESSAGE_SIZE as u16,
            vec![0u8; INIT_DATA_SIZE],
        );

        assert!(matches!(res, Ok(None)));
    }
}
