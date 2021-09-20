use crate::config::Config;
use crate::context::*;
use crate::error::Error;
use pcap_parser::{PcapBlockOwned, PcapError};
use std::io::Read;

pub trait BlockAnalyzer {
    /// Initialization function, called before reading pcap data (optional)
    fn init(&mut self) -> Result<(), Error> {
        Ok(())
    }
    /// Callback function for every block of the pcap/pcapng file
    fn handle_block(
        &mut self,
        _block: &PcapBlockOwned,
        _block_ctx: &ParseBlockContext,
    ) -> Result<(), Error>;

    /// Teardown function, called after reading pcap data (optional)
    fn teardown(&mut self) {}

    fn before_refill(&mut self) {}
}

pub struct BlockEngine<A: BlockAnalyzer> {
    analyzer: A,

    capacity: usize,
}

impl<A: BlockAnalyzer> BlockEngine<A> {
    pub fn new(analyzer: A, config: &Config) -> Self {
        let capacity = config
            .get_usize("buffer_initial_capacity")
            .unwrap_or(128 * 1024);
        BlockEngine { analyzer, capacity }
    }

    pub fn analyzer(&self) -> &A {
        &self.analyzer
    }

    /// Main function: given a reader, read all pcap data and call analyzer for each Packet
    pub fn run(&mut self, reader: &mut dyn Read) -> Result<(), Error> {
        let mut reader = pcap_parser::create_reader(self.capacity, reader)?;

        self.analyzer.init()?;
        let mut ctx = ParseBlockContext::default();
        let mut last_incomplete_index = 0;

        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    self.analyzer.handle_block(&block, &ctx)?;
                    ctx.block_index += 1;
                    reader.consume_noshift(offset);
                    continue;
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete) => {
                    if last_incomplete_index == ctx.block_index {
                        warn!(
                            "Could not read complete data block (block_index={})",
                            ctx.block_index
                        );
                        warn!(
                            "  Buffer: consumed={} position={}",
                            reader.consumed(),
                            reader.position()
                        );
                        warn!("Hint: the reader buffer size may be too small, or the input file may be truncated.");
                        break;
                    }
                    last_incomplete_index = ctx.block_index;
                    // refill the buffer
                    debug!("need refill");
                    self.analyzer.before_refill();
                    reader.refill().map_err(|e| e.to_owned_vec())?;
                    continue;
                }
                Err(e) => {
                    let e = e.to_owned_vec();
                    error!("error while reading: {:?}", e);
                    error!(
                        "  Buffer: consumed={} position={}",
                        reader.consumed(),
                        reader.position()
                    );
                    return Err(Error::Pcap(e));
                }
            }
        }

        self.analyzer.teardown();
        Ok(())
    }
}
