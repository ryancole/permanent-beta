//! Answer key for the `basic` fixture, built with /O2 /OPT:ICF. The map files in tests/data are real
//! linker output from corpus/build-fixtures.ps1; regenerate them if the fixture sources change.

use permanent_beta_corpus::{
    map,
    truth::{GroundTruth, Scope},
};
use permanent_beta_model::Rva;

fn truth() -> GroundTruth {
    let old = map::parse(include_str!("data/basic-o2-icf-v1.map")).unwrap();
    let new = map::parse(include_str!("data/basic-o2-icf-v2.map")).unwrap();
    GroundTruth::from_maps(&old, &new, &Scope::Object("fixture.obj".into()))
}

#[test]
fn every_scenario_is_present() {
    let t = truth();
    for name in [
        "main",
        "pb_unchanged",
        "pb_moved",
        "pb_body_edited",
        "pb_param_added",
        "pb_struct_reader",
        "pb_dup_a",
        "pb_dup_b",
        "pb_deleted",
        "pb_added",
        "pb_static_strings",
    ] {
        assert!(t.entry(name).is_some(), "{name} missing from truth");
    }
}

#[test]
fn deleted_and_added_have_one_side_only() {
    let t = truth();
    let deleted = t.entry("pb_deleted").unwrap();
    assert!(deleted.old.is_some() && deleted.new.is_none());
    let added = t.entry("pb_added").unwrap();
    assert!(added.old.is_none() && added.new.is_some());
}

#[test]
fn icf_folds_the_duplicates_into_one_entry() {
    let t = truth();
    let dup = t.entry("pb_dup_a").unwrap();
    assert_eq!(dup.names, vec!["pb_dup_a", "pb_dup_b"]);
    assert_eq!((dup.old, dup.new), (Some(Rva(0x10e0)), Some(Rva(0x10f0))));
}

#[test]
fn static_function_is_flagged() {
    let t = truth();
    assert!(t.entry("pb_static_strings").unwrap().is_static);
    assert!(!t.entry("pb_moved").unwrap().is_static);
}

#[test]
fn crt_functions_are_out_of_scope() {
    let t = truth();
    assert!(t.entry("mainCRTStartup").is_none());
}
