use super::{Command, CommandResult, Context};

pub struct BuildersCmd;
impl Command for BuildersCmd {
    fn run(&self, args: &[&str], ctx: &mut Context) -> CommandResult {
        if args.len() < 2 {
            return CommandResult::Error {
                errmsg: Some("usage: builders <subcmd> [<args>]"),
                fatal: false,
            };
        }
        match args[1] {
            "list" => {
                println!("Available plugin builders:");
                ctx.factory.iter_builders(|name| println!("  {}", name));
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
        "Configure plugin builders"
    }
}
