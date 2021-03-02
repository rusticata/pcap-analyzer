use super::{Command, CommandResult, Context};
use libpcap_analyzer::*;
use libpcap_tools::{PcapDataEngine, PcapEngine};
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

pub struct AnalyzeCmd;
impl Command for AnalyzeCmd {
    fn run(&self, _args: &[&str], ctx: &mut Context) -> CommandResult {
        // log::debug!("running analyzer");
        let file = match &mut ctx.file {
            Some(f) => f,
            None => {
                return CommandResult::Error {
                    errmsg: Some("analyze: no file loaded"),
                    fatal: false,
                }
            }
        };
        let registry = ctx
            .factory
            .build_plugins(&ctx.config)
            .expect("Could not instantiate plugin registry");
        {
            let input_reader = file.by_ref();
            // let input_reader = file;
            let analyzer = Analyzer::new(Arc::new(registry), &ctx.config);
            let mut engine = PcapDataEngine::new(analyzer, &ctx.config);
            engine.run(input_reader).expect("running analyzer failed");
            ctx.engine = Some(engine);
        }
        let _ = file.seek(SeekFrom::Start(0));
        CommandResult::Ok
    }

    fn help(&self) -> &'static str {
        "Run analyzer"
    }
}
