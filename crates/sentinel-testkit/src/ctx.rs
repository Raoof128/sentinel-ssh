//! An `AppContext` over the minimal config and a scripted backend.

use std::ops::Deref;
use std::sync::Arc;

use sentinel_gateway::tools::AppContext;

use crate::configs::{TestDirs, load_minimal};
use crate::fake_backend::FakeBackend;

pub struct TestCtx {
    pub ctx: AppContext,
    pub dirs: TestDirs,
}

impl Deref for TestCtx {
    type Target = AppContext;
    fn deref(&self) -> &AppContext {
        &self.ctx
    }
}

pub fn ctx_with(fake: FakeBackend) -> TestCtx {
    let dirs = TestDirs::new();
    let (cfg, _) = load_minimal(&dirs);
    TestCtx {
        ctx: AppContext::new(cfg, Arc::new(fake)).expect("context"),
        dirs,
    }
}
