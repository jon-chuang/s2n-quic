// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{inet::datagram, path};

/// A structure capable of queueing and receiving messages
pub trait Queue {
    type Entry: Entry<Handle = Self::Handle>;
    type Handle: path::Handle;

    fn pop(&mut self) -> Option<Self::Entry>;

    fn finish(&mut self, entry: Self::Entry);
}

/// An entry in a Rx queue
pub trait Entry {
    type Handle: path::Handle;

    /// Returns the datagram information with the datagram payload
    fn next_segment(&mut self) -> Option<(datagram::Header<Self::Handle>, &mut [u8])>;
}
