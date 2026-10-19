//! Fast2Ban implementation of fail2ban-regex.

pub mod config;
pub mod console;
pub mod optparse;
pub mod pyrepr;
pub mod runner;
pub mod textwrap;

use std::rc::Rc;

use f2b_config::RealFs;
use f2b_date::LocalZone;

use crate::config::make_parser;
use crate::console::{err_raw, flush, out};
use crate::optparse::Parsed;
use crate::runner::Fail2banRegex;

/// Run the CLI with the given command line arguments (`argv[0]` included).
pub fn run(args: Vec<String>) -> i32 {
    let argv0 = args
        .first()
        .cloned()
        .unwrap_or_else(|| "fail2ban-regex".to_owned());
    let parser = make_parser(&argv0);
    let parsed = parser.parse(&args[1..]);

    let (opts, positional) = match parsed {
        Parsed::Run(vals, pos) => (vals, pos),
        Parsed::Exit {
            code,
            stdout,
            stderr,
        } => {
            if !stdout.is_empty() {
                crate::console::out_raw(&stdout);
            }
            if !stderr.is_empty() {
                err_raw(&stderr);
            }
            flush();
            return code;
        }
    };

    let mut errors = Vec::new();
    if opts.flag("print_no_missed") && opts.flag("print_all_missed") {
        errors.push("ERROR: --print-no-missed and --print-all-missed are mutually exclusive.");
    }
    if opts.flag("print_no_ignored") && opts.flag("print_all_ignored") {
        errors.push("ERROR: --print-no-ignored and --print-all-ignored are mutually exclusive.");
    }
    if !(positional.len() == 2 || positional.len() == 3) {
        errors.push("ERROR: provide both <LOG> and <REGEX>.");
    }

    if !errors.is_empty() {
        crate::console::out_raw(&parser.format_help());
        let mut err_msg = String::from("\n");
        err_msg.push_str(&errors.join("\n"));
        err_msg.push('\n');
        err_raw(&err_msg);
        flush();
        return 255;
    }

    if opts.str("out").is_none() {
        out("");
        out("Running tests");
        out("=============");
        out("");
    }

    let tz_env = std::env::var("TZ").ok();
    let local_zone = tz_env
        .as_deref()
        .and_then(|tz| LocalZone::from_tz_value(tz).ok())
        .unwrap_or_else(LocalZone::system);

    let fs = Rc::new(RealFs);
    let mut app = match Fail2banRegex::new(opts, local_zone, fs) {
        Ok(a) => a,
        Err(e) => {
            out(&format!("ERROR: {e}"));
            flush();
            return 255;
        }
    };

    let ok = match app.start(&positional) {
        Ok(ok) => ok,
        Err(e) => {
            out(&format!("ERROR: {e}"));
            false
        }
    };

    flush();
    if ok { 0 } else { 255 }
}
