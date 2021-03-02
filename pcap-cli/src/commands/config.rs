use super::{Command, CommandResult, Context};

pub struct ConfigCmd;
impl Command for ConfigCmd {
    fn run(&self, args: &[&str], ctx: &mut Context) -> CommandResult {
        if args.len() < 2 {
            return CommandResult::Error {
                errmsg: Some("usage: config <subcmd> [<args>]"),
                fatal: false,
            };
        }
        match args[1] {
            "get" => {
                let res = ctx.config.get(args[2]);
                println!("config[{}]: '{}'", args[2], res.unwrap_or("<NONE>"));
                CommandResult::Ok
            }
            "set" => {
                ctx.config.set(args[2], args[3]);
                CommandResult::Ok
            }
            _ => {
                CommandResult::Error {
                    errmsg: Some("usage: builders <subcmd> [<args>]"),
                    fatal: false,
                }
            }
        }
    }

    fn help(&self) -> &'static str {
        "Configure options"
    }
}
