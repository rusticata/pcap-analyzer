use super::{Command, CommandResult, Context};

pub struct EngineCmd;
impl Command for EngineCmd {
    fn run(&self, args: &[&str], ctx: &mut Context) -> CommandResult {
        if args.len() < 2 {
            return CommandResult::Error {
                errmsg: Some("usage: engine <subcmd> [<args>]"),
                fatal: false,
            };
        }
        let engine = match ctx.engine {
            Some(ref e) => e,
            None => {
                return CommandResult::Error {
                    errmsg: Some(
                        "engine not created yet (did you forgot to run the 'analyze' command?",
                    ),
                    fatal: false,
                }
            }
        };
        let analyzer = engine.data_analyzer();
        match args[1] {
            "get" => {
                let wanted = args[2];
                // dbg!(wanted);
                let all = wanted == "all";
                // for (_plugin_info, p) in analyzer.registry().iter_plugins() {
                //     let p = p.lock().unwrap();
                //     println!("{}", p.name());
                // }
                analyzer.registry().run_plugins(
                    |p| all || p.name() == wanted,
                    |p| {
                        //
                        print!("{}: ", p.name());
                        let res = p.get_results();
                        // dbg!(&res);
                        if let Some(res) = res {
                            if let Ok(v) = res.downcast::<serde_json::Value>() {
                                //
                                println!("{}", v);
                            } else {
                                println!();
                                eprintln!("value is not a known result type");
                            }
                        } else {
                            println!("<no value>");
                        }
                    },
                );
                CommandResult::Ok
            }
            "set" => {
                unimplemented!();
                // CommandResult::Ok
            }
            "list-plugins" => {
                for p in analyzer.registry().iter_plugins() {
                    let p = p.lock().unwrap();
                    println!("{}", p.name());
                }
                CommandResult::Ok
            }
            "list-registered-plugins" => {
                for (info, p) in analyzer.registry().iter_registered_plugins() {
                    let p = p.lock().unwrap();
                    println!(
                        "{} (layer {} / filter {})",
                        p.name(),
                        info.layer,
                        info.layer_filter
                    );
                }
                CommandResult::Ok
            }
            _ => {
                CommandResult::Error {
                    errmsg: Some("unknown engine subcmd"),
                    fatal: false,
                }
            }
        }
    }

    fn help(&self) -> &'static str {
        "Access to pcap engine / analyzer results"
    }
}
