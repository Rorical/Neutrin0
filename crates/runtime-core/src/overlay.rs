//! Disposable state journal for runtime simulation and atomic block execution.

use crate::StateBackend;
use alloc::{collections::BTreeMap, vec::Vec};
use neutrin0_primitives::StateRoot;

/// An overlay commits only when its owner explicitly flushes a successful transition.
pub struct OverlayState<'a, B: StateBackend> {
    inner: &'a mut B,
    changes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl<'a, B: StateBackend> OverlayState<'a, B> {
    /// Open a disposable journal against the selected authenticated state.
    pub const fn new(inner: &'a mut B) -> Self {
        Self {
            inner,
            changes: BTreeMap::new(),
        }
    }
    /// Publish all journaled writes after successful execution.
    pub fn flush(&mut self) {
        for (key, value) in core::mem::take(&mut self.changes) {
            match value {
                Some(value) => self.inner.write(&key, value),
                None => self.inner.delete(&key),
            }
        }
    }
}

impl<B: StateBackend> StateBackend for OverlayState<'_, B> {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.changes
            .get(key)
            .cloned()
            .unwrap_or_else(|| self.inner.read(key))
    }
    fn write(&mut self, key: &[u8], value: Vec<u8>) {
        self.changes.insert(key.to_vec(), Some(value));
    }
    fn delete(&mut self, key: &[u8]) {
        self.changes.insert(key.to_vec(), None);
    }
    fn pre_state_root(&self) -> StateRoot {
        self.inner.pre_state_root()
    }
    fn post_state_root(&self) -> StateRoot {
        assert!(
            self.changes.is_empty(),
            "flush successful execution before computing its root"
        );
        self.inner.post_state_root()
    }
}
