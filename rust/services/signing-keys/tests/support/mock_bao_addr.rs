//! Scoped test-only binding for a loopback OpenBao mock origin.

use std::ffi::OsString;

static BAO_ADDR_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub struct MockBaoAddr {
    previous: Option<OsString>,
    _lock: tokio::sync::MutexGuard<'static, ()>,
}

impl Drop for MockBaoAddr {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            std::env::set_var("BAO_ADDR", previous);
        } else {
            std::env::remove_var("BAO_ADDR");
        }
    }
}

pub async fn mock_bao_addr(endpoint: &str) -> MockBaoAddr {
    let lock = BAO_ADDR_LOCK.lock().await;
    let previous = std::env::var_os("BAO_ADDR");
    std::env::set_var("BAO_ADDR", endpoint);
    MockBaoAddr {
        previous,
        _lock: lock,
    }
}
