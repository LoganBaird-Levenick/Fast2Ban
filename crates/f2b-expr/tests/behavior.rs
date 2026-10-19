//! Behaviour the oracle grid cannot express: resource bounds, the random-source
//! contract of `BanTimeIncrement::calc`, and `Num` conversions.

use f2b_expr::{BanTimeIncrement, BanTimeOptions, ExprError, Num, seconds2str, str2seconds};
use std::cell::Cell;

fn increment(formula: Option<&str>, rndtime: Option<&str>) -> BanTimeIncrement {
    BanTimeIncrement::new(&BanTimeOptions {
        formula,
        rndtime,
        ..BanTimeOptions::default()
    })
    .expect("valid options")
}

#[test]
fn hostile_input_is_an_error_not_a_panic() {
    let deep_parens = format!("{}1{}", "(".repeat(100_000), ")".repeat(100_000));
    let deep_unary = format!("{}1", "-".repeat(100_000));
    let long_chain = "1+".repeat(50_000) + "1";
    for bad in [
        deep_parens,
        deep_unary,
        long_chain,
        "\0".into(),
        "\u{1}".into(),
    ] {
        assert!(str2seconds(&bad).is_err(), "{:.20}", bad);
        let opts = BanTimeOptions {
            formula: Some(&bad),
            ..BanTimeOptions::default()
        };
        assert!(BanTimeIncrement::new(&opts).is_err());
    }
    // within the documented limits deep nesting still works
    assert_eq!(
        str2seconds(&format!("{}7{}", "(".repeat(90), ")".repeat(90))),
        Ok(Num::Int(7))
    );
    assert_eq!(
        str2seconds(&format!("{}7", "-".repeat(90))),
        Ok(Num::Int(7))
    );
}

#[test]
fn rand_is_called_once_and_only_when_rndtime_is_set() {
    let calls = Cell::new(0);
    let rand = || {
        calls.set(calls.get() + 1);
        0.5
    };
    let plain = increment(None, None);
    assert_eq!(plain.calc(Num::Int(600), 1, rand), Ok(Num::Int(1200)));
    assert_eq!(calls.get(), 0);

    let rnd = increment(None, Some("5m"));
    // 600 * 2 = 1200, + 0.5 * 300 -> float, like `int + float` in Python
    assert_eq!(rnd.calc(Num::Int(600), 1, rand), Ok(Num::Float(1350.0)));
    assert_eq!(calls.get(), 1);

    // evaluation failing first: random() is never reached
    let failing = increment(Some("ban.Time / (ban.Count - 1)"), Some("5m"));
    assert!(failing.calc(Num::Int(600), 1, rand).is_err());
    assert_eq!(calls.get(), 1);
}

#[test]
fn default_formula_stops_growing_at_count_20() {
    let inc = increment(None, None);
    let at = |c| inc.calc(Num::Int(1), c, || 0.0).unwrap();
    assert_eq!(at(19), Num::Int(1 << 19));
    assert_eq!(at(20), Num::Int(1 << 20));
    assert_eq!(at(21), Num::Int(1 << 20));
    assert_eq!(at(500), Num::Int(1 << 20));
}

#[test]
fn formula_problems_surface_at_construction() {
    for bad in [
        "ban.Time *",
        "ban.nope",
        "unknown_name * 2",
        "ban",
        "ban.Time(1)",
        "min(1)",
        "abs()",
        "'a'",
    ] {
        let opts = BanTimeOptions {
            formula: Some(bad),
            ..BanTimeOptions::default()
        };
        assert!(BanTimeIncrement::new(&opts).is_err(), "{bad}");
    }
    let opts = BanTimeOptions {
        factor: Some("ban.Time"),
        ..BanTimeOptions::default()
    };
    assert!(
        BanTimeIncrement::new(&opts).is_err(),
        "factor cannot see ban.*"
    );
    let opts = BanTimeOptions {
        maxtime: Some("1x"),
        ..BanTimeOptions::default()
    };
    assert!(BanTimeIncrement::new(&opts).is_err());
}

#[test]
fn integer_overflow_is_reported_not_wrapped() {
    assert!(matches!(
        str2seconds("9223372036854775807+1"),
        Err(ExprError::Overflow(_))
    ));
    assert!(matches!(str2seconds("2**63"), Err(ExprError::Overflow(_))));
    assert_eq!(
        str2seconds("2**62*2-1+2**62*2"),
        Err(ExprError::Overflow("integer multiplication"))
    );
    assert_eq!(str2seconds("9223372036854775807"), Ok(Num::Int(i64::MAX)));
}

#[test]
fn num_conversions_follow_python_int_and_float() {
    assert_eq!(Num::Float(-2.9).as_i64(), Ok(-2));
    assert_eq!(Num::Float(2629800.0).as_i64(), Ok(2_629_800));
    assert!(Num::Float(f64::NAN).as_i64().is_err());
    assert!(Num::Float(f64::INFINITY).as_i64().is_err());
    assert!(Num::Float(9.3e18).as_i64().is_err());
    assert_eq!(Num::Int(3600).as_f64(), 3600.0);
    assert_eq!(Num::Int(3600).to_string(), "3600");
    assert_eq!(Num::Float(3600.0).to_string(), "3600.0");
    assert_eq!(Num::Float(1e16).to_string(), "1e+16");
}

#[test]
fn documented_examples() {
    assert_eq!(str2seconds("1h"), Ok(Num::Int(3600)));
    assert_eq!(str2seconds("1month"), Ok(Num::Float(2_629_800.0)));
    assert_eq!(str2seconds("600"), Ok(Num::Int(600)));
    assert_eq!(str2seconds("1.5"), Ok(Num::Float(1.5)));
    assert_eq!(str2seconds("-1"), Ok(Num::Int(-1)));
    assert_eq!(
        seconds2str(Num::Int(86400 * 390)).as_deref(),
        Ok("1y 3w 4d")
    );
    assert_eq!(seconds2str(Num::Int(0)).as_deref(), Ok("0"));
    assert_eq!(seconds2str(Num::Float(90.5)).as_deref(), Ok("1.0m 30.5s"));
}
