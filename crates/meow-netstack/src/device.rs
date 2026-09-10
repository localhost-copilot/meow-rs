use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use std::collections::VecDeque;

pub(crate) struct RawIp {
    pub incoming: VecDeque<Vec<u8>>,
    pub outgoing: VecDeque<Vec<u8>>,
    pub mtu: usize,
}

pub(crate) struct Received(Vec<u8>);
impl RxToken for Received {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

pub(crate) struct Transmit<'a>(&'a mut VecDeque<Vec<u8>>);
impl TxToken for Transmit<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}

impl Device for RawIp {
    type RxToken<'a> = Received;
    type TxToken<'a> = Transmit<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Received, Transmit<'_>)> {
        if self.outgoing.len() >= 64 {
            return None;
        }
        Some((
            Received(self.incoming.pop_front()?),
            Transmit(&mut self.outgoing),
        ))
    }
    fn transmit(&mut self, _: Instant) -> Option<Transmit<'_>> {
        (self.outgoing.len() < 64).then_some(Transmit(&mut self.outgoing))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}
