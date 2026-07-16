//! Block-related consensus types.

mod header;
pub use header::{BlockHeader, BlockHeaderMut, GasLimitMismatch, Header};

mod traits;
pub use traits::EthBlock;

mod meta;
pub use meta::{HeaderInfo, HeaderRoots};

#[cfg(all(feature = "serde", feature = "serde-bincode-compat"))]
pub(crate) use header::serde_bincode_compat;

use crate::Transaction;
use alloc::vec::Vec;
use alloy_eips::{eip2718::WithEncoded, eip4895::Withdrawals, Encodable2718, Typed2718};
use alloy_primitives::{keccak256, Bytes, Sealable, Sealed, B256};
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};

/// Ethereum full block.
///
/// Withdrawals can be optionally included at the end of the RLP encoded message.
///
/// Taken from [reth-primitives](https://github.com/paradigmxyz/reth)
///
/// See p2p block encoding reference: <https://github.com/ethereum/devp2p/blob/master/caps/eth.md#block-encoding-and-validity>
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Deref)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct Block<T, H = Header> {
    /// Block header.
    #[deref]
    pub header: H,
    /// Block body.
    pub body: BlockBody<T, H>,
}

impl<T, H> Block<T, H> {
    /// Creates a new block with the given header and body.
    pub const fn new(header: H, body: BlockBody<T, H>) -> Self {
        Self { header, body }
    }

    /// Creates a new empty uncle block.
    pub fn uncle(header: H) -> Self {
        Self { header, body: Default::default() }
    }

    /// Consumes the block and returns the header.
    pub fn into_header(self) -> H {
        self.header
    }

    /// Consumes the block and returns the body.
    pub fn into_body(self) -> BlockBody<T, H> {
        self.body
    }

    /// Converts the block's header type by applying a function to it.
    pub fn map_header<U>(self, mut f: impl FnMut(H) -> U) -> Block<T, U> {
        Block { header: f(self.header), body: self.body.map_ommers(f) }
    }

    /// Converts the block's header type by applying a fallible function to it.
    pub fn try_map_header<U, E>(
        self,
        mut f: impl FnMut(H) -> Result<U, E>,
    ) -> Result<Block<T, U>, E> {
        Ok(Block { header: f(self.header)?, body: self.body.try_map_ommers(f)? })
    }

    /// Converts the block's transaction type to the given alternative that is `From<T>`
    pub fn convert_transactions<U>(self) -> Block<U, H>
    where
        U: From<T>,
    {
        self.map_transactions(U::from)
    }

    /// Converts the block's transaction to the given alternative that is `TryFrom<T>`
    ///
    /// Returns the block with the new transaction type if all conversions were successful.
    pub fn try_convert_transactions<U>(self) -> Result<Block<U, H>, U::Error>
    where
        U: TryFrom<T>,
    {
        self.try_map_transactions(U::try_from)
    }

    /// Converts the block's transaction type by applying a function to each transaction.
    ///
    /// Returns the block with the new transaction type.
    pub fn map_transactions<U>(self, f: impl FnMut(T) -> U) -> Block<U, H> {
        Block {
            header: self.header,
            body: BlockBody {
                transactions: self.body.transactions.into_iter().map(f).collect(),
                ommers: self.body.ommers,
                withdrawals: self.body.withdrawals,
                slashed: self.body.slashed,
                bridge_requests: self.body.bridge_requests,
            },
        }
    }

    /// Converts the block's transaction type by applying a fallible function to each transaction.
    ///
    /// Returns the block with the new transaction type if all transactions were successfully.
    pub fn try_map_transactions<U, E>(
        self,
        f: impl FnMut(T) -> Result<U, E>,
    ) -> Result<Block<U, H>, E> {
        Ok(Block {
            header: self.header,
            body: BlockBody {
                transactions: self
                    .body
                    .transactions
                    .into_iter()
                    .map(f)
                    .collect::<Result<_, _>>()?,
                ommers: self.body.ommers,
                withdrawals: self.body.withdrawals,
                slashed: self.body.slashed,
                bridge_requests: self.body.bridge_requests,
            },
        })
    }

    /// Converts the transactions in the block's body to `WithEncoded<T>` by encoding them via
    /// [`Encodable2718`]
    pub fn into_with_encoded2718(self) -> Block<WithEncoded<T>, H>
    where
        T: Encodable2718,
    {
        self.map_transactions(|tx| tx.into_encoded())
    }

    /// Replaces the header of the block.
    ///
    /// Note: This method only replaces the main block header. If you need to transform
    /// the ommer headers as well, use [`map_header`](Self::map_header) instead.
    pub fn with_header(mut self, header: H) -> Self {
        self.header = header;
        self
    }

    /// Encodes the [`Block`] given header and block body.
    ///
    /// Returns the rlp encoded block.
    ///
    /// This is equivalent to `block.encode`.
    pub fn rlp_encoded_from_parts(header: &H, body: &BlockBody<T, H>) -> Vec<u8>
    where
        H: Encodable,
        T: Encodable,
    {
        let helper = block_rlp::HelperRef::from_parts(header, body);
        let mut buf = Vec::with_capacity(helper.length());
        helper.encode(&mut buf);
        buf
    }

    /// Encodes the [`Block`] given header and block body
    ///
    /// This is equivalent to `block.encode`.
    pub fn rlp_encode_from_parts(
        header: &H,
        body: &BlockBody<T, H>,
        out: &mut dyn alloy_rlp::bytes::BufMut,
    ) where
        H: Encodable,
        T: Encodable,
    {
        block_rlp::HelperRef::from_parts(header, body).encode(out)
    }

    /// Returns the RLP encoded length of the block's header and body.
    pub fn rlp_length_for(header: &H, body: &BlockBody<T, H>) -> usize
    where
        H: Encodable,
        T: Encodable,
    {
        block_rlp::HelperRef::from_parts(header, body).length()
    }
}

impl<T: Encodable2718> Block<T, Header> {
    /// Creates a new block from a header and an iterator of transactions.
    ///
    /// Computes and sets the `transactions_root` on the header automatically.
    /// `ommers_hash` is set to [`EMPTY_OMMER_ROOT_HASH`](crate::EMPTY_OMMER_ROOT_HASH).
    pub fn from_transactions(
        mut header: Header,
        transactions: impl IntoIterator<Item = T>,
    ) -> Self {
        let transactions: Vec<T> = transactions.into_iter().collect();
        header.transactions_root = crate::proofs::calculate_transaction_root(&transactions);
        header.ommers_hash = crate::EMPTY_OMMER_ROOT_HASH;
        Self::new(
            header,
            BlockBody {
                transactions,
                ommers: Vec::new(),
                withdrawals: None,
                slashed: None,
                bridge_requests: None,
            },
        )
    }
}

impl<T, H> Default for Block<T, H>
where
    H: Default,
{
    fn default() -> Self {
        Self { header: Default::default(), body: Default::default() }
    }
}

impl<T, H> From<Block<T, H>> for BlockBody<T, H> {
    fn from(block: Block<T, H>) -> Self {
        block.into_body()
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a, T, H> arbitrary::Arbitrary<'a> for Block<T, H>
where
    T: arbitrary::Arbitrary<'a>,
    H: arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { header: u.arbitrary()?, body: u.arbitrary()? })
    }
}

/// A response to `GetBlockBodies`, containing bodies if any bodies were found.
///
/// Withdrawals can be optionally included at the end of the RLP encoded message.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[rlp(trailing)]
pub struct BlockBody<T, H = Header> {
    /// Transactions in this block.
    pub transactions: Vec<T>,
    /// Ommers/uncles header.
    pub ommers: Vec<H>,
    /// Block withdrawals.
    pub withdrawals: Option<Withdrawals>,
    /// Slashed validator entries (0G extension, not part of the block hash).
    pub slashed: Option<Withdrawals>,
    /// 0G: CL-determined `BridgeRequests` SSZ blob, carried verbatim (the data portion of the
    /// EIP-7685 type-`0xf0` requests entry, without the type byte). `Some` (at least 4 bytes,
    /// the SSZ empty-list offset) iff the Bridge fork is active at the block timestamp; `None`
    /// on all pre-Bridge blocks, which keeps their RLP encoding byte-identical to the
    /// pre-extension format. Not hashed into the body roots: the block hash already commits to
    /// these bytes through the header's `requests_hash`. Must never be `Some` of empty bytes —
    /// an empty-bytes RLP item (`0x80`) is indistinguishable from the trailing-optional
    /// placeholder emitted for a `None` field that precedes a `Some` field.
    pub bridge_requests: Option<Bytes>,
}

impl<T, H> Default for BlockBody<T, H> {
    fn default() -> Self {
        Self {
            transactions: Vec::new(),
            ommers: Vec::new(),
            withdrawals: None,
            slashed: None,
            bridge_requests: None,
        }
    }
}

impl<T, H> BlockBody<T, H> {
    /// Returns an iterator over all transactions.
    #[inline]
    pub fn transactions(&self) -> impl Iterator<Item = &T> + '_ {
        self.transactions.iter()
    }

    /// Create a [`Block`] from the body and its header.
    pub const fn into_block(self, header: H) -> Block<T, H> {
        Block { header, body: self }
    }

    /// Calculate the ommers root for the block body.
    pub fn calculate_ommers_root(&self) -> B256
    where
        H: Encodable,
    {
        crate::proofs::calculate_ommers_root(&self.ommers)
    }

    /// Returns an iterator over the hashes of the ommers in the block body.
    pub fn ommers_hashes(&self) -> impl Iterator<Item = B256> + '_
    where
        H: Sealable,
    {
        self.ommers.iter().map(|h| h.hash_slow())
    }

    /// Calculate the withdrawals root for the block body, if withdrawals exist. If there are no
    /// withdrawals, this will return `None`.
    pub fn calculate_withdrawals_root(&self) -> Option<B256> {
        self.withdrawals.as_ref().map(|w| crate::proofs::calculate_withdrawals_root(w))
    }

    /// Converts the body's ommers type by applying a function to it.
    pub fn map_ommers<U>(self, f: impl FnMut(H) -> U) -> BlockBody<T, U> {
        BlockBody {
            transactions: self.transactions,
            ommers: self.ommers.into_iter().map(f).collect(),
            withdrawals: self.withdrawals,
            slashed: self.slashed,
            bridge_requests: self.bridge_requests,
        }
    }

    /// Converts the body's ommers type by applying a fallible function to it.
    pub fn try_map_ommers<U, E>(
        self,
        f: impl FnMut(H) -> Result<U, E>,
    ) -> Result<BlockBody<T, U>, E> {
        Ok(BlockBody {
            transactions: self.transactions,
            ommers: self.ommers.into_iter().map(f).collect::<Result<Vec<_>, _>>()?,
            withdrawals: self.withdrawals,
            slashed: self.slashed,
            bridge_requests: self.bridge_requests,
        })
    }
}

impl<T: Transaction, H> BlockBody<T, H> {
    /// Returns an iterator over all blob versioned hashes from the block body.
    #[inline]
    pub fn blob_versioned_hashes_iter(&self) -> impl Iterator<Item = &B256> + '_ {
        self.eip4844_transactions_iter().filter_map(|tx| tx.blob_versioned_hashes()).flatten()
    }
}

impl<T: Typed2718, H> BlockBody<T, H> {
    /// Returns whether or not the block body contains any blob transactions.
    #[inline]
    pub fn has_eip4844_transactions(&self) -> bool {
        self.transactions.iter().any(|tx| tx.is_eip4844())
    }

    /// Returns whether or not the block body contains any EIP-7702 transactions.
    #[inline]
    pub fn has_eip7702_transactions(&self) -> bool {
        self.transactions.iter().any(|tx| tx.is_eip7702())
    }

    /// Returns an iterator over all blob transactions of the block.
    #[inline]
    pub fn eip4844_transactions_iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.transactions.iter().filter(|tx| tx.is_eip4844())
    }
}

/// We need to implement RLP traits manually because we currently don't have a way to flatten
/// [`BlockBody`] into [`Block`].
mod block_rlp {
    use super::*;

    #[derive(RlpDecodable)]
    #[rlp(trailing)]
    struct Helper<T, H> {
        header: H,
        transactions: Vec<T>,
        ommers: Vec<H>,
        withdrawals: Option<Withdrawals>,
        slashed: Option<Withdrawals>,
        bridge_requests: Option<Bytes>,
    }

    #[derive(RlpEncodable)]
    #[rlp(trailing)]
    pub(crate) struct HelperRef<'a, T, H> {
        pub(crate) header: &'a H,
        pub(crate) transactions: &'a Vec<T>,
        pub(crate) ommers: &'a Vec<H>,
        pub(crate) withdrawals: Option<&'a Withdrawals>,
        pub(crate) slashed: Option<&'a Withdrawals>,
        pub(crate) bridge_requests: Option<&'a Bytes>,
    }

    impl<'a, T, H> HelperRef<'a, T, H> {
        pub(crate) fn from_parts(header: &'a H, body: &'a BlockBody<T, H>) -> Self {
            Self {
                header,
                transactions: &body.transactions,
                ommers: &body.ommers,
                withdrawals: body.withdrawals.as_ref(),
                slashed: body.slashed.as_ref(),
                // Normalize `Some(empty)` -> `None`: an empty-bytes RLP item (0x80) is
                // indistinguishable from the trailing-optional placeholder emitted for a `None`
                // field, so encoding `Some(empty)` and decoding it back silently yields `None`.
                // Coercing here makes that forbidden state unrepresentable on the wire and keeps
                // encode/decode a faithful round-trip.
                bridge_requests: body.bridge_requests.as_ref().filter(|b| !b.is_empty()),
            }
        }
    }

    impl<'a, T, H> From<&'a Block<T, H>> for HelperRef<'a, T, H> {
        fn from(block: &'a Block<T, H>) -> Self {
            let Block {
                header,
                body: BlockBody { transactions, ommers, withdrawals, slashed, bridge_requests },
            } = block;
            Self {
                header,
                transactions,
                ommers,
                withdrawals: withdrawals.as_ref(),
                slashed: slashed.as_ref(),
                // Normalize `Some(empty)` -> `None`: an empty-bytes RLP item (0x80) collides with
                // the trailing-optional placeholder for a `None` field, so the round-trip would
                // silently turn `Some(empty)` into `None`. Coerce it away on the wire.
                bridge_requests: bridge_requests.as_ref().filter(|b| !b.is_empty()),
            }
        }
    }

    impl<T: Encodable, H: Encodable> Encodable for Block<T, H> {
        fn encode(&self, out: &mut dyn alloy_rlp::bytes::BufMut) {
            let helper: HelperRef<'_, T, H> = self.into();
            helper.encode(out)
        }

        fn length(&self) -> usize {
            let helper: HelperRef<'_, T, H> = self.into();
            helper.length()
        }
    }

    impl<T: Decodable, H: Decodable> Decodable for Block<T, H> {
        fn decode(b: &mut &[u8]) -> alloy_rlp::Result<Self> {
            let Helper { header, transactions, ommers, withdrawals, slashed, bridge_requests } =
                Helper::decode(b)?;
            Ok(Self {
                header,
                body: BlockBody { transactions, ommers, withdrawals, slashed, bridge_requests },
            })
        }
    }

    impl<T: Decodable, H: Decodable> Block<T, H> {
        /// Decodes the block from RLP, computing the header hash directly from the RLP bytes.
        ///
        /// This is more efficient than decoding the block and then sealing it, as the header
        /// hash is computed from the raw RLP bytes without re-encoding.
        pub fn decode_sealed(buf: &mut &[u8]) -> alloy_rlp::Result<Sealed<Self>> {
            // Decode the outer block list header
            let block_rlp_head = alloy_rlp::Header::decode(buf)?;
            if !block_rlp_head.list {
                return Err(alloy_rlp::Error::UnexpectedString);
            }

            // Decode header and compute hash from raw RLP bytes
            let header_start = *buf;
            let header = H::decode(buf)?;
            let header_hash = keccak256(&header_start[..header_start.len() - buf.len()]);

            // Decode remaining body fields
            let transactions = Vec::<T>::decode(buf)?;
            let ommers = Vec::<H>::decode(buf)?;
            let withdrawals =
                if buf.is_empty() { None } else { Option::<Withdrawals>::decode(buf)? };
            let slashed =
                if buf.is_empty() { None } else { Option::<Withdrawals>::decode(buf)? };
            let bridge_requests = if buf.is_empty() {
                None
            } else {
                Option::<Bytes>::decode(buf)?.filter(|requests| !requests.is_empty())
            };

            let block = Self {
                header,
                body: BlockBody {
                    transactions,
                    ommers,
                    withdrawals,
                    slashed,
                    bridge_requests,
                },
            };

            Ok(Sealed::new_unchecked(block, header_hash))
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a, T, H> arbitrary::Arbitrary<'a> for BlockBody<T, H>
where
    T: arbitrary::Arbitrary<'a>,
    H: arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // first generate up to 100 txs
        let transactions = (0..u.int_in_range(0..=100)?)
            .map(|_| T::arbitrary(u))
            .collect::<arbitrary::Result<Vec<_>>>()?;

        // then generate up to 2 ommers
        let ommers = (0..u.int_in_range(0..=1)?)
            .map(|_| H::arbitrary(u))
            .collect::<arbitrary::Result<Vec<_>>>()?;

        // `Some` of empty bytes is forbidden for `bridge_requests` (its RLP item would collide
        // with the trailing-optional placeholder), so filter empties out of arbitrary data.
        let bridge_requests = u
            .arbitrary::<Option<alloc::vec::Vec<u8>>>()?
            .filter(|b| !b.is_empty())
            .map(Bytes::from);

        Ok(Self {
            transactions,
            ommers,
            withdrawals: u.arbitrary()?,
            slashed: u.arbitrary()?,
            bridge_requests,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Signed, TxEnvelope, TxLegacy};
    use alloy_eips::eip4895::{Withdrawal, Withdrawals};
    use alloy_primitives::address;
    use alloy_rlp::{Decodable, Encodable};

    #[test]
    fn can_convert_block() {
        let block: Block<Signed<TxLegacy>> = Block::default();
        let _: Block<TxEnvelope> = block.convert_transactions();
    }

    #[test]
    fn decode_sealed_produces_correct_hash() {
        let block: Block<TxEnvelope> = Block::default();
        let expected_hash = block.header.hash_slow();

        let mut encoded = Vec::new();
        block.encode(&mut encoded);

        let mut buf = encoded.as_slice();
        let sealed = Block::<TxEnvelope>::decode_sealed(&mut buf).unwrap();

        assert_eq!(sealed.hash(), expected_hash);
        assert_eq!(*sealed.inner(), block);
    }

    #[test]
    fn header_decode_sealed_produces_correct_hash() {
        let header = Header::default();
        let expected_hash = header.hash_slow();

        let mut encoded = Vec::new();
        header.encode(&mut encoded);

        let mut buf = encoded.as_slice();
        let sealed = Header::decode_sealed(&mut buf).unwrap();

        assert_eq!(sealed.hash(), expected_hash);
        assert_eq!(*sealed.inner(), header);
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_sealed_roundtrip_with_transactions() {
        use crate::{SignableTransaction, TxLegacy};
        use alloy_primitives::{Address, Signature, TxKind, U256};

        let tx = TxLegacy {
            nonce: 1,
            gas_price: 100,
            gas_limit: 21000,
            to: TxKind::Call(Address::ZERO),
            value: U256::from(1000),
            input: Default::default(),
            chain_id: Some(1),
        };
        let sig = Signature::new(U256::from(1), U256::from(2), false);
        let signed = tx.into_signed(sig);
        let envelope: TxEnvelope = signed.into();

        let block = Block {
            header: Header { number: 42, gas_limit: 30_000_000, ..Default::default() },
            body: BlockBody {
                transactions: vec![envelope],
                ommers: vec![],
                withdrawals: None,
                slashed: None,
                bridge_requests: None,
            },
        };

        let expected_hash = block.header.hash_slow();

        let mut encoded = Vec::new();
        block.encode(&mut encoded);

        let mut buf = encoded.as_slice();
        let sealed = Block::<TxEnvelope>::decode_sealed(&mut buf).unwrap();

        assert_eq!(sealed.hash(), expected_hash);
        assert_eq!(sealed.header.number, 42);
        assert_eq!(sealed.body.transactions.len(), 1);
        assert!(buf.is_empty());
    }

    #[test]
    fn block_body_rejects_present_string_withdrawals() {
        let mut omitted: &[u8] = &[0xc2, 0xc0, 0xc0];
        let body = BlockBody::<TxEnvelope>::decode(&mut omitted).unwrap();
        assert!(body.withdrawals.is_none());
        assert!(omitted.is_empty());

        let mut present_empty: &[u8] = &[0xc3, 0xc0, 0xc0, 0xc0];
        let body = BlockBody::<TxEnvelope>::decode(&mut present_empty).unwrap();
        assert!(body.withdrawals.as_ref().is_some_and(|w| w.is_empty()));
        assert!(present_empty.is_empty());

        let mut present_string: &[u8] = &[0xc3, 0xc0, 0xc0, 0x80];
        assert!(BlockBody::<TxEnvelope>::decode(&mut present_string).is_err());
    }

    #[test]
    fn block_decoders_reject_present_string_withdrawals() {
        fn block_rlp_with_body_fields(body_fields: &[u8]) -> Vec<u8> {
            let mut header = Vec::new();
            Header::default().encode(&mut header);

            let block_header =
                alloy_rlp::Header { list: true, payload_length: header.len() + body_fields.len() };
            let mut out = Vec::with_capacity(block_header.length_with_payload());
            block_header.encode(&mut out);
            out.extend_from_slice(&header);
            out.extend_from_slice(body_fields);
            out
        }

        let omitted = block_rlp_with_body_fields(&[0xc0, 0xc0]);
        assert!(Block::<TxEnvelope>::decode(&mut omitted.as_slice()).is_ok());
        assert!(Block::<TxEnvelope>::decode_sealed(&mut omitted.as_slice()).is_ok());

        let present_empty = block_rlp_with_body_fields(&[0xc0, 0xc0, 0xc0]);
        assert!(Block::<TxEnvelope>::decode(&mut present_empty.as_slice()).is_ok());
        assert!(Block::<TxEnvelope>::decode_sealed(&mut present_empty.as_slice()).is_ok());

        let present_string = block_rlp_with_body_fields(&[0xc0, 0xc0, 0x80]);
        assert!(Block::<TxEnvelope>::decode(&mut present_string.as_slice()).is_err());
        assert!(Block::<TxEnvelope>::decode_sealed(&mut present_string.as_slice()).is_err());
    }

    #[test]
    fn block_body_slashed_rlp_roundtrip() {
        let body = BlockBody::<TxEnvelope, Header> {
            transactions: vec![],
            ommers: vec![],
            withdrawals: Some(Withdrawals::default()),
            slashed: Some(Withdrawals::new(vec![Withdrawal {
                index: 0,
                validator_index: 42,
                address: address!("0000000000000000000000000000000000000001"),
                amount: 1_000_000_000,
            }])),
            bridge_requests: None,
        };

        let mut encoded = Vec::new();
        body.encode(&mut encoded);

        let decoded = BlockBody::<TxEnvelope, Header>::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(body, decoded);
    }

    /// The pre-`bridge_requests` body shape (transactions, ommers, withdrawals, slashed) with
    /// identical RLP derives — used to prove byte-level encoding compatibility below.
    #[derive(Debug, PartialEq, RlpEncodable, RlpDecodable)]
    #[rlp(trailing)]
    struct PreBridgeBlockBody<T, H> {
        transactions: Vec<T>,
        ommers: Vec<H>,
        withdrawals: Option<Withdrawals>,
        slashed: Option<Withdrawals>,
    }

    fn sample_withdrawals() -> Withdrawals {
        Withdrawals::new(vec![Withdrawal {
            index: 7,
            validator_index: u64::MAX,
            address: address!("00000000000000000000000000000000000000aa"),
            amount: 123_456,
        }])
    }

    /// SSZ encoding of an empty `BridgeRequests { messages: [] }` container: a single 4-byte
    /// offset. This is the smallest blob the CL ever emits post-Bridge.
    const EMPTY_BRIDGE_SSZ: [u8; 4] = [0x04, 0x00, 0x00, 0x00];

    /// A body with `bridge_requests: None` must encode byte-identically to the pre-extension
    /// struct, so pre-Bridge blocks keep their historical devp2p/storage encoding and old and
    /// new binaries interoperate before the fork.
    #[test]
    fn block_body_pre_bridge_encoding_byte_identical() {
        let cases: Vec<(Option<Withdrawals>, Option<Withdrawals>)> = vec![
            (None, None),
            (Some(Withdrawals::default()), None),
            (Some(sample_withdrawals()), None),
            (Some(sample_withdrawals()), Some(sample_withdrawals())),
        ];
        for (withdrawals, slashed) in cases {
            let old = PreBridgeBlockBody::<TxEnvelope, Header> {
                transactions: vec![],
                ommers: vec![],
                withdrawals: withdrawals.clone(),
                slashed: slashed.clone(),
            };
            let new = BlockBody::<TxEnvelope, Header> {
                transactions: vec![],
                ommers: vec![],
                withdrawals,
                slashed,
                bridge_requests: None,
            };

            let mut old_encoded = Vec::new();
            old.encode(&mut old_encoded);
            let mut new_encoded = Vec::new();
            new.encode(&mut new_encoded);
            assert_eq!(old_encoded, new_encoded, "pre-Bridge encoding changed");

            // Old bytes decode into the new struct with bridge_requests = None.
            let decoded =
                BlockBody::<TxEnvelope, Header>::decode(&mut old_encoded.as_slice()).unwrap();
            assert_eq!(decoded, new);
        }
    }

    /// `slashed: None` + `bridge_requests: Some` exercises the trailing-optional placeholder
    /// (`0x80`) the RLP derive writes for the interior `None`; it must round-trip.
    #[test]
    fn block_body_bridge_placeholder_roundtrip() {
        let bodies = vec![
            // withdrawals Some, slashed None, bridge Some — the common post-fork shape
            BlockBody::<TxEnvelope, Header> {
                transactions: vec![],
                ommers: vec![],
                withdrawals: Some(sample_withdrawals()),
                slashed: None,
                bridge_requests: Some(Bytes::from(EMPTY_BRIDGE_SSZ.to_vec())),
            },
            // both interior options None, bridge Some — two placeholders
            BlockBody::<TxEnvelope, Header> {
                transactions: vec![],
                ommers: vec![],
                withdrawals: None,
                slashed: None,
                bridge_requests: Some(Bytes::from(vec![0xde, 0xad, 0xbe, 0xef, 0x01])),
            },
            // everything Some
            BlockBody::<TxEnvelope, Header> {
                transactions: vec![],
                ommers: vec![],
                withdrawals: Some(sample_withdrawals()),
                slashed: Some(sample_withdrawals()),
                bridge_requests: Some(Bytes::from(vec![0x04, 0x00, 0x00, 0x00, 0xff, 0x11])),
            },
        ];
        for body in bodies {
            let mut encoded = Vec::new();
            body.encode(&mut encoded);
            let decoded =
                BlockBody::<TxEnvelope, Header>::decode(&mut encoded.as_slice()).unwrap();
            assert_eq!(body, decoded);
        }
    }

    /// `bridge_requests: Some(empty)` is a forbidden state (its RLP item `0x80` collides with
    /// the trailing-optional `None` placeholder). The whole-`Block` encoder (HelperRef)
    /// normalizes it to `None`, so a block whose body carries `Some(empty)` must (a) encode
    /// byte-identically to the same block with `None`, and (b) decode back with
    /// `bridge_requests == None` — never `Some(empty)`, which would otherwise be a silent
    /// encode/decode mismatch.
    #[test]
    fn block_bridge_some_empty_normalizes_to_none() {
        let some_empty = Block::<TxEnvelope, Header> {
            header: Header::default(),
            body: BlockBody {
                transactions: vec![],
                ommers: vec![],
                withdrawals: Some(sample_withdrawals()),
                slashed: None,
                bridge_requests: Some(Bytes::new()),
            },
        };
        let none = Block::<TxEnvelope, Header> {
            body: BlockBody { bridge_requests: None, ..some_empty.body.clone() },
            ..some_empty.clone()
        };

        let mut enc_some_empty = Vec::new();
        some_empty.encode(&mut enc_some_empty);
        let mut enc_none = Vec::new();
        none.encode(&mut enc_none);
        assert_eq!(enc_some_empty, enc_none, "Some(empty) must encode identically to None");

        let decoded = Block::<TxEnvelope, Header>::decode(&mut enc_some_empty.as_slice()).unwrap();
        assert_eq!(
            decoded.body.bridge_requests, None,
            "Some(empty) must decode back as None"
        );
    }

    /// Same guarantees at the whole-`Block` level (the hand-written Helper/HelperRef RLP).
    #[test]
    fn block_rlp_pre_bridge_identity_and_bridge_roundtrip() {
        #[derive(RlpEncodable)]
        #[rlp(trailing)]
        struct PreBridgeBlockRef<'a, T, H> {
            header: &'a H,
            transactions: &'a Vec<T>,
            ommers: &'a Vec<H>,
            withdrawals: Option<&'a Withdrawals>,
            slashed: Option<&'a Withdrawals>,
        }

        // pre-Bridge block: byte identity with the old encoding
        let block = Block::<TxEnvelope, Header> {
            header: Header::default(),
            body: BlockBody {
                transactions: vec![],
                ommers: vec![],
                withdrawals: Some(sample_withdrawals()),
                slashed: None,
                bridge_requests: None,
            },
        };
        let old = PreBridgeBlockRef {
            header: &block.header,
            transactions: &block.body.transactions,
            ommers: &block.body.ommers,
            withdrawals: block.body.withdrawals.as_ref(),
            slashed: block.body.slashed.as_ref(),
        };
        let mut old_encoded = Vec::new();
        old.encode(&mut old_encoded);
        let mut new_encoded = Vec::new();
        block.encode(&mut new_encoded);
        assert_eq!(old_encoded, new_encoded, "pre-Bridge Block encoding changed");
        let decoded = Block::<TxEnvelope, Header>::decode(&mut old_encoded.as_slice()).unwrap();
        assert_eq!(decoded, block);

        // post-Bridge block: placeholder + blob round-trip
        let block = Block::<TxEnvelope, Header> {
            header: Header::default(),
            body: BlockBody {
                transactions: vec![],
                ommers: vec![],
                withdrawals: Some(sample_withdrawals()),
                slashed: None,
                bridge_requests: Some(Bytes::from(EMPTY_BRIDGE_SSZ.to_vec())),
            },
        };
        let mut encoded = Vec::new();
        block.encode(&mut encoded);
        let decoded = Block::<TxEnvelope, Header>::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded, block);
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod fuzz_tests {
    use super::*;
    use crate::{EthereumTxEnvelope, TxEip4844};
    use alloy_rlp::Encodable;
    use arbitrary::{Arbitrary, Unstructured};
    use rand::Rng;

    #[test]
    fn fuzz_decode_sealed_block_roundtrip() {
        for _ in 0..10 {
            let mut bytes = [0u8; 1024 * 1024];
            rand::thread_rng().fill(bytes.as_mut_slice());
            let mut u = Unstructured::new(&bytes);

            let block = Block::<EthereumTxEnvelope<TxEip4844>>::arbitrary(&mut u).unwrap();
            let expected_hash = block.header.hash_slow();

            let mut encoded = Vec::new();
            block.encode(&mut encoded);

            let sealed =
                Block::<EthereumTxEnvelope<TxEip4844>>::decode_sealed(&mut encoded.as_slice())
                    .unwrap();
            assert_eq!(sealed.hash(), expected_hash);
            assert_eq!(*sealed.inner(), block);
        }
    }

    #[test]
    fn fuzz_header_decode_sealed_roundtrip() {
        for _ in 0..200 {
            let mut bytes = [0u8; 1024];
            rand::thread_rng().fill(bytes.as_mut_slice());
            let mut u = Unstructured::new(&bytes);

            let header = Header::arbitrary(&mut u).unwrap();
            let expected_hash = header.hash_slow();

            let mut encoded = Vec::new();
            header.encode(&mut encoded);

            let mut buf = encoded.as_slice();
            let sealed = Header::decode_sealed(&mut buf).unwrap();

            assert_eq!(sealed.hash(), expected_hash);
            assert_eq!(*sealed.inner(), header);
        }
    }
}
