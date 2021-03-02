use super::{Command, CommandResult, Context};
use pcap_parser::{create_reader, pcapng::Block, PcapBlockOwned};
use std::io::{Read, Seek, SeekFrom};

pub struct InfoCmd;
impl Command for InfoCmd {
    fn run(&self, _args: &[&str], ctx: &mut Context) -> CommandResult {
        if let Some(f) = &mut ctx.file {
            let md = f.metadata().unwrap();
            println!("{} bytes", md.len());
            {
                let file_reader = f.by_ref();
                let mut reader = create_reader(128 * 1024, file_reader).expect("reader");
                let first_block = reader.next();
                match first_block {
                    Ok((_sz, PcapBlockOwned::LegacyHeader(_hdr))) => {
                        println!("Type: Legacy Pcap");
                    }
                    Ok((_sz, PcapBlockOwned::NG(Block::SectionHeader(ref _shb)))) => {
                        println!("Type: Pcap-NG");
                    }
                    _ => {
                        return CommandResult::Error {
                            errmsg: Some("Neither a pcap nor pcap-ng header was found"),
                            fatal: true,
                        };
                    }
                }
            }
            let _ = f.seek(SeekFrom::Start(0));
        } else {
            println!("no file loaded");
        }
        CommandResult::Ok
    }

    fn help(&self) -> &'static str {
        "Show information about loaded file, if present"
    }
}
