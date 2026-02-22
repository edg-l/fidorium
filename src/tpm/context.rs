use super::{TpmError, keys};
use std::sync::{Arc, Mutex};
use tss_esapi::handles::KeyHandle;
use tss_esapi::{Context, TctiNameConf};

struct TpmContextInner {
    ctx: Mutex<Context>,
    primary: KeyHandle,
}

#[derive(Clone)]
pub struct TpmContext {
    inner: Arc<TpmContextInner>,
}

impl TpmContext {
    pub fn new(device_path: &str) -> Result<Self, TpmError> {
        let tcti_str = format!("device:{device_path}");
        let tcti = tcti_str
            .parse::<TctiNameConf>()
            .map_err(|e| TpmError::Context(e.to_string()))?;
        let mut ctx = Context::new(tcti).map_err(|e| TpmError::Context(e.to_string()))?;
        let primary = keys::create_primary(&mut ctx)?;
        Ok(Self {
            inner: Arc::new(TpmContextInner {
                ctx: Mutex::new(ctx),
                primary,
            }),
        })
    }

    /// Run a synchronous TPM operation. Call from spawn_blocking.
    pub fn with_ctx<F, T>(&self, f: F) -> Result<T, TpmError>
    where
        F: FnOnce(&mut Context, KeyHandle) -> Result<T, TpmError>,
    {
        let mut ctx = self
            .inner
            .ctx
            .lock()
            .map_err(|_| TpmError::Context("mutex poisoned".into()))?;
        f(&mut ctx, self.inner.primary)
    }
}
