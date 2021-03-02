use crate::context::Context;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::fs::File;

mod analyze;
mod builders;
mod config;
mod engine;
mod info;

pub enum CommandResult {
    Ok,
    Error {
        errmsg: Option<&'static str>,
        fatal: bool,
    },
    Exit {
        rc: i32,
    },
}

pub trait Command: Sync {
    fn run(&self, args: &[&str], ctx: &mut Context) -> CommandResult;

    fn help(&self) -> &'static str {
        "no help provided"
    }
}

pub struct EchoCmd;
impl Command for EchoCmd {
    fn run(&self, args: &[&str], _ctx: &mut Context) -> CommandResult {
        println!("{}", &args[1..].join(" "));
        CommandResult::Ok
    }

    fn help(&self) -> &'static str {
        "Display a line of text"
    }
}

pub struct ExitCmd;
impl Command for ExitCmd {
    fn run(&self, _args: &[&str], _ctx: &mut Context) -> CommandResult {
        CommandResult::Exit { rc: 0 }
    }

    fn help(&self) -> &'static str {
        "Exit pcap-cli"
    }
}

pub struct HelpCmd;
impl Command for HelpCmd {
    fn run(&self, _args: &[&str], _ctx: &mut Context) -> CommandResult {
        println!("Available commands:");
        for (name, cmd) in COMMANDS.iter() {
            println!("  {}: {}", name, cmd.help());
        }
        CommandResult::Ok
    }

    fn help(&self) -> &'static str {
        "Show documentation"
    }
}

pub struct LoadCmd;
impl Command for LoadCmd {
    fn run(&self, args: &[&str], ctx: &mut Context) -> CommandResult {
        if args.len() != 2 {
            return CommandResult::Error {
                errmsg: Some("load: need input file name"),
                fatal: false,
            };
        }
        log::info!("loading '{}'", args[1]);
        let file = File::open(args[1]).unwrap();
        ctx.file = Some(file);
        CommandResult::Ok
    }

    fn help(&self) -> &'static str {
        "Load file to memory"
    }
}

lazy_static! {
    static ref COMMANDS: HashMap<&'static str, Box<dyn Command>> = {
        let mut m = HashMap::new();
        m.insert("analyze", Box::new(analyze::AnalyzeCmd) as Box<_>);
        m.insert("builders", Box::new(builders::BuildersCmd) as Box<_>);
        m.insert("config", Box::new(config::ConfigCmd) as Box<_>);
        m.insert("echo", Box::new(EchoCmd) as Box<_>);
        m.insert("engine", Box::new(engine::EngineCmd) as Box<_>);
        m.insert("exit", Box::new(ExitCmd) as Box<_>);
        m.insert("help", Box::new(HelpCmd) as Box<_>);
        m.insert("info", Box::new(info::InfoCmd) as Box<_>);
        m.insert("load", Box::new(LoadCmd) as Box<_>);
        m
    };
}

pub fn dispatch(line: &str, ctx: &mut Context) -> CommandResult {
    // split words
    let v: Vec<&str> = line.split(' ').collect();
    if v.is_empty() || v[0].is_empty() {
        return CommandResult::Ok;
    }
    if let Some(cmd) = COMMANDS.get(v[0]) {
        cmd.run(&v, ctx)
    } else {
        log::warn!("unknown command '{}'", v[0]);
        CommandResult::Error {
            errmsg: Some("Unknown command"),
            fatal: false,
        }
    }
}
