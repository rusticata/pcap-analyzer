use clap::crate_version;
use log::LevelFilter;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::{
    env,
    fs::File,
    io::{BufRead, BufReader},
};

mod commands;
mod context;
use commands::CommandResult;

fn main() {
    println!("pcap-cli {}", crate_version!());

    // Create an Editor with the default configuration options.
    let mut repl = Editor::<()>::new().expect("could not create repl editor");
    // Load a file with the history of commands
    // If the file does not exists, it creates one.
    if repl.load_history("history.txt").is_err() {
        println!("No previous history.");
    }

    let mut args = env::args();

    let log_level = LevelFilter::Debug;
    fern::Dispatch::new()
        .format(|out, message, record| {
            let now = time::OffsetDateTime::now_local().unwrap();
            let format = time::format_description::parse("[hour]:[minute]:[second]").unwrap();
            out.finish(format_args!(
                "{} [{}] [{}] {}",
                now.format(&format).unwrap(),
                record.level(),
                record.target(),
                message
            ))
        })
        .level(log_level)
        .level_for("rustyline", log::LevelFilter::Warn)
        .chain(std::io::stdout())
        .apply()
        .unwrap();
    let mut ctx = context::Context::default();

    if args.len() > 1 {
        let file_name = args.nth(1).unwrap();
        // a file name was provided, run in non-interactive mode
        let f = File::open(file_name).unwrap();
        let reader = BufReader::new(f);
        for line in reader.lines() {
            let line = line.unwrap();
            // println!("line: '{}'", line);
            if line.starts_with('#') {
                // comment
                continue;
            }
            match commands::dispatch(&line, &mut ctx) {
                CommandResult::Ok => (),
                CommandResult::Error { errmsg, fatal } => {
                    if let Some(e) = errmsg {
                        eprintln!("{}", e);
                    }
                    if fatal {
                        std::process::exit(-1);
                    }
                }
                CommandResult::Exit { rc } => std::process::exit(rc),
            }
        }
        return;
    }

    loop {
        let readline = repl.readline(">> ");
        match readline {
            Ok(line) => {
                if !line.is_empty() {
                    repl.add_history_entry(line.as_str());
                }
                let line = line.trim_end();
                if line.starts_with('#') {
                    // comment
                    continue;
                }
                // println!("Line: {}", line);
                match commands::dispatch(line, &mut ctx) {
                    CommandResult::Ok => (),
                    CommandResult::Error { errmsg, fatal } => {
                        if let Some(e) = errmsg {
                            eprintln!("{}", e);
                        }
                        if fatal {
                            break;
                        }
                    }
                    CommandResult::Exit { rc } => {
                        repl.save_history("history.txt").unwrap();
                        std::process::exit(rc)
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                break;
            }
        }
        repl.save_history("history.txt").unwrap();
    }
}
