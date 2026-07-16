use super::Block;
use alloy_eips::eip4895::Withdrawals;
use alloy_primitives::Bytes;

/// A trait for ethereum like blocks.
pub trait EthBlock {
    /// Returns reference to withdrawals in the block if present
    fn withdrawals(&self) -> Option<&Withdrawals>;

    /// Returns reference to slashed validator entries in the block if present.
    fn slashed(&self) -> Option<&Withdrawals> {
        None
    }

    /// Returns reference to the 0G bridge-requests SSZ blob carried in the block body, if
    /// present (post-Bridge-fork blocks only).
    fn bridge_requests(&self) -> Option<&Bytes> {
        None
    }
}

impl<T, H> EthBlock for Block<T, H> {
    fn withdrawals(&self) -> Option<&Withdrawals> {
        self.body.withdrawals.as_ref()
    }

    fn slashed(&self) -> Option<&Withdrawals> {
        self.body.slashed.as_ref()
    }

    fn bridge_requests(&self) -> Option<&Bytes> {
        self.body.bridge_requests.as_ref()
    }
}
