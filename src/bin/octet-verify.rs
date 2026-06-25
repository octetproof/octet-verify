//! `octet-verify` — independent CLI verifier for Octet `LocationProof` artifacts.
//!
//! Reads a binary-encoded `octet.proof.LocationProof` (or, with
//! `--envelope`, an `octet.attest.ContinuousProofEnvelope`) from a file or
//! stdin, checks its authenticity and integrity, and prints a per-check report.
//!
//! Exit codes: 0 = valid · 1 = invalid (a check failed) · 2 = usage/IO/decode.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use octet_verify::attest::ContinuousProofEnvelope;
use octet_verify::crypto::P256VerifyingKey;
use octet_verify::navigate::LocationProof;
use octet_verify::prost::Message;
use octet_verify::verify::{verify, verify_transport, Report, Status, VerifyOptions};
use octet_verify::{keys, verify as verify_mod};

const DEFAULT_MAX_AGE_S: i64 = 300;

#[derive(Default)]
struct Args {
    path: Option<String>,
    hardware_pubkey: Option<String>,
    ed25519_pubkey: Option<String>,
    envelope: bool,
    max_age_s: Option<i64>,
    nullifier_store: Option<String>,
    expect_region: Option<String>,
    app_attest_config: Option<String>,
    skip_hardware_attestation: bool,
    json: bool,
}

fn main() -> ExitCode {
    // Subcommand dispatch. `fetch`/`watch`/`range` go to the backend client
    // (feature = "net"); anything else — including a bare file path — stays the
    // existing local-file verifier, whose logic below is unchanged.
    let argv: Vec<String> = std::env::args().collect();
    match argv.get(1).map(String::as_str) {
        Some("fetch") | Some("watch") | Some("range") => return backend_dispatch(&argv[1..]),
        _ => {}
    }
    local_main()
}

fn local_main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\nrun `octet-verify --help` for usage");
            return ExitCode::from(2);
        }
    };

    match run(&args) {
        Ok(report) => {
            if args.json {
                print_json(&report);
            } else {
                print_human(&report);
            }
            exit_code(&report)
        }
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &Args) -> anyhow::Result<Report> {
    let bytes = read_input(args.path.as_deref())?;

    // Unwrap the transport envelope if asked; otherwise the input is a bare proof.
    type Unwrapped = (Vec<u8>, Option<Vec<u8>>, Option<octet_verify::replay::ReplayControl>);
    let (proof_bytes, transport_sig, replay_control): Unwrapped = if args.envelope {
        let env = ContinuousProofEnvelope::decode(&*bytes)
            .map_err(|e| anyhow::anyhow!("failed to decode ContinuousProofEnvelope: {e}"))?;
        let rc = env.replay_control.map(octet_verify::replay::ReplayControl::from);
        (env.proof_bytes, Some(env.proof_signature), rc)
    } else {
        (bytes, None, None)
    };

    let proof = LocationProof::decode(&*proof_bytes)
        .map_err(|e| anyhow::anyhow!("failed to decode LocationProof: {e}"))?;

    // Resolve the hardware key: explicit flag wins, else the proof's chain.
    let (hw_key, hw_source) = resolve_hardware_key(&proof, args.hardware_pubkey.as_deref())?;

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    let opts = VerifyOptions {
        now_ms,
        max_age_s: args.max_age_s.unwrap_or(DEFAULT_MAX_AGE_S),
        hardware_pubkey: hw_key.as_ref(),
        hw_key_source: &hw_source,
        expect_region: args.expect_region.as_deref(),
    };

    let mut report = verify(&proof, &opts);

    // Wire-format guard: reject a proof that smuggles a duplicate of a
    // non-repeated proto field (prost silently keeps the last value).
    report.checks.push(wire_check(&proof_bytes));

    // Replay-control binding: in --envelope mode, bind the envelope's
    // replay_control to the signed proof (same check the backend-fetch path
    // runs). A bare proof carries no envelope, so the check applies only here; a
    // v1 envelope (no replay_control) reports NOT-CHECKED.
    if args.envelope {
        report
            .checks
            .push(octet_verify::replay::check_replay_binding(&proof, replay_control.as_ref()));
    }

    // Ed25519 transport signature (only meaningful in --envelope mode).
    if let Some(sig) = &transport_sig {
        match &args.ed25519_pubkey {
            Some(p) => {
                let vk = keys::load_ed25519_pubkey(&PathBuf::from(p))?;
                report.checks.push(verify_transport(&proof_bytes, sig, &vk));
            }
            None => report.checks.push(verify_mod::Check {
                name: "ed25519-transport",
                status: Status::NotChecked,
                detail: "envelope carries a transport signature but no --ed25519-pubkey was given".into(),
            }),
        }
    }

    // Optional cross-run replay detection.
    if let Some(store) = &args.nullifier_store {
        report.checks.push(replay_check(store, &proof.nullifier)?);
    }

    // Offline hardware-attestation layer: App Attest, the Android key-attestation
    // chain, and the field-2 device-key signature. `--skip-hardware-attestation`
    // scopes an `appattest` build to core verification only (e.g. triaging a
    // legacy or synthetic proof that carries no real attestation chain).
    if !args.skip_hardware_attestation {
        // Optional offline App Attest verification (feature `appattest`). Expected
        // app identity comes from the shared octet-attest-verify TOML config — one
        // location, nothing hardcoded.
        if let Some(cfg_path) = &args.app_attest_config {
            #[cfg(feature = "appattest")]
            report.checks.push(appattest_from_config(&proof, cfg_path)?);
            #[cfg(not(feature = "appattest"))]
            {
                let _ = cfg_path;
                report.checks.push(verify_mod::Check {
                    name: "app-attest",
                    status: Status::NotChecked,
                    detail: "--app-attest-config given but this binary was built without the `appattest` feature".into(),
                });
            }
        }

        // Android key-attestation chain → Google root, plus the field-2 device-key
        // signature (feature `appattest`). Both need no config — only the proof and
        // the resolved hardware key — so they run whenever the feature is built.
        // verify() omits its NOT-CHECKED placeholders under this feature (cfg-gated
        // there), so the layer is the sole source of these verdicts.
        #[cfg(feature = "appattest")]
        {
            // iOS proofs (no cert chain) report attestation-root NOT-CHECKED and
            // rely on the app-attest check above instead.
            let now_unix_secs = (now_ms / 1000).max(0) as u64;
            report
                .checks
                .push(octet_verify::appattest_layer::attestation_root_check(
                    &proof,
                    now_unix_secs,
                ));

            let pubkey_sec1 = hw_key.as_ref().map(|vk| vk.to_sec1_bytes());
            report
                .checks
                .push(octet_verify::appattest_layer::device_signature_check(
                    &proof,
                    pubkey_sec1.as_deref(),
                ));
        }
    }

    Ok(report)
}

/// Load the shared App Attest config and verify the proof's evidence against it.
#[cfg(feature = "appattest")]
fn appattest_from_config(
    proof: &octet_verify::navigate::LocationProof,
    cfg_path: &str,
) -> anyhow::Result<verify_mod::Check> {
    use octet_attest_verify::config::Config;
    use octet_verify::appattest_layer::{appattest_check, Expectation};

    let cfg = Config::from_file(cfg_path)
        .map_err(|e| anyhow::anyhow!("app-attest config: {e}"))?;
    let aa = cfg
        .app_attest
        .ok_or_else(|| anyhow::anyhow!("app-attest config has no [app_attest] section"))?;
    let expect = Expectation::new(&aa.team_id, &aa.bundle_id, aa.environment.into());
    // Stateless single-proof check: no cached key, so an assertion-only proof
    // reports NOT-CHECKED (it needs the attestation object or a cached key).
    let (check, _key) = appattest_check(proof, &expect, None);
    Ok(check)
}

/// Detect (and record) reuse of a nullifier across runs using a simple
/// newline-delimited hex file. Appends on first sighting.
///
/// **Best-effort, single-process only.** The read-check-append is not atomic and
/// holds no lock, so two concurrent invocations against the same store can both
/// miss a duplicate (TOCTOU) — this is a local/offline auditing convenience, not
/// a concurrency-safe or authoritative replay defense. Authoritative cross-proof
/// uniqueness is enforced server-side at ingest, where the cross-proof state
/// actually lives.
fn replay_check(store_path: &str, nullifier: &[u8]) -> anyhow::Result<verify_mod::Check> {
    use std::io::Write;
    let hex = to_hex(nullifier);
    let existing = std::fs::read_to_string(store_path).unwrap_or_default();
    let seen = existing.lines().any(|l| l.trim() == hex);
    if seen {
        return Ok(verify_mod::Check {
            name: "replay",
            status: Status::Fail,
            detail: format!("nullifier already present in {store_path}"),
        });
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(store_path)
        .map_err(|e| anyhow::anyhow!("opening nullifier store {store_path}: {e}"))?;
    writeln!(f, "{hex}").map_err(|e| anyhow::anyhow!("writing nullifier store: {e}"))?;
    Ok(verify_mod::Check {
        name: "replay",
        status: Status::Pass,
        detail: "nullifier not seen before; recorded".into(),
    })
}

/// Resolve the hardware P-256 key a proof's stage chain is verified against:
/// an explicit `--hardware-pubkey` file wins, otherwise the key is pulled from
/// the proof's own certificate chain. Returns the key (if any) and a
/// human-readable provenance string for the report. Shared by the local-file
/// path and the backend fetch path so both resolve keys identically.
fn resolve_hardware_key(
    proof: &LocationProof,
    flag: Option<&str>,
) -> anyhow::Result<(Option<P256VerifyingKey>, String)> {
    match flag {
        Some(p) => Ok((
            Some(keys::load_hardware_pubkey(&PathBuf::from(p))?),
            "--hardware-pubkey".into(),
        )),
        None => match proof.device_attestation.as_ref() {
            Some(da) if !da.certificate_chain.is_empty() => {
                match keys::hardware_pubkey_from_cert_chain(&da.certificate_chain) {
                    Ok(vk) => Ok((Some(vk), "certificate_chain".into())),
                    Err(e) => Ok((None, format!("certificate_chain present but unreadable: {e}"))),
                }
            }
            _ => Ok((None, "none (no certificate_chain; supply --hardware-pubkey)".into())),
        },
    }
}

fn read_input(path: Option<&str>) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    match path {
        Some(p) => std::fs::read(p).map_err(|e| anyhow::anyhow!("reading {p}: {e}")),
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| anyhow::anyhow!("reading stdin: {e}"))?;
            if buf.is_empty() {
                anyhow::bail!("no input — pass a file path or pipe bytes on stdin");
            }
            Ok(buf)
        }
    }
}

// --- reporting ---

/// Headline reflects assurance precisely: a passing structure with unverified
/// signatures is INCONCLUSIVE, never VALID.
fn headline(report: &Report) -> &'static str {
    if !report.is_valid() {
        return "INVALID";
    }
    if report.sigs_verified() {
        "VALID"
    } else {
        "INCONCLUSIVE (signatures not verified)"
    }
}

/// Tri-state CLI exit code — the single source of truth for every command:
///   `0` = authentic (VALID) · `1` = invalid (a check failed) ·
///   `3` = inconclusive (structure ok, signatures not verified).
/// `2` is reserved for usage / IO / decode / backend errors (returned
/// elsewhere). INCONCLUSIVE is deliberately non-zero so that
/// `octet-verify … && deploy` can never treat an unverified proof as success.
fn exit_code(report: &Report) -> ExitCode {
    if !report.is_valid() {
        ExitCode::from(1)
    } else if report.sigs_verified() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    }
}

fn print_human(report: &Report) {
    println!("== octet-verify ==");
    println!("verdict: {}", headline(report));
    println!();
    for c in &report.checks {
        println!("  [{:>11}] {:<22} {}", c.status.tag(), c.name, sanitize_terminal(&c.detail));
    }
    println!();
    println!(
        "{} pass · {} fail · {} warn · {} not-checked",
        report.count(Status::Pass),
        report.count(Status::Fail),
        report.count(Status::Warn),
        report.count(Status::NotChecked),
    );
}

fn print_json(report: &Report) {
    let mut out = String::from("{\n");
    // `valid` reflects AUTHENTICITY (not rejected AND signatures verified), so a
    // consumer keying on it can't be fooled by a structurally-fine but
    // signature-unverified proof. `verdict` carries the full tri-state string
    // (VALID / INCONCLUSIVE / INVALID) and `signatures_verified` exposes the
    // crypto bit directly, so a careful consumer can still tell the states apart.
    out.push_str(&format!("  \"verdict\": \"{}\",\n", headline(report)));
    out.push_str(&format!("  \"valid\": {},\n", report.is_authentic()));
    out.push_str(&format!("  \"signatures_verified\": {},\n", report.sigs_verified()));
    out.push_str("  \"checks\": [\n");
    for (i, c) in report.checks.iter().enumerate() {
        let comma = if i + 1 < report.checks.len() { "," } else { "" };
        out.push_str(&format!(
            "    {{\"name\": \"{}\", \"status\": \"{}\", \"detail\": \"{}\"}}{}\n",
            c.name,
            c.status.tag(),
            json_escape(&c.detail),
            comma
        ));
    }
    out.push_str("  ]\n}");
    println!("{out}");
}

/// Reject a proof that smuggles a duplicate of a non-repeated proto field —
/// prost keeps the last value silently, so an appended second `timestamp_ms`
/// (etc.) makes this verifier and another parser disagree. A `Fail` here makes
/// the proof INVALID. See `octet_verify::wire`.
fn wire_check(proof_bytes: &[u8]) -> verify_mod::Check {
    let dups = octet_verify::wire::duplicate_singular_fields(proof_bytes);
    if dups.is_empty() {
        verify_mod::Check {
            name: "wire-format",
            status: Status::Pass,
            detail: "no duplicate non-repeated proto fields".into(),
        }
    } else {
        let names: Vec<String> = dups
            .iter()
            .map(|f| format!("{} (field {f})", octet_verify::wire::field_name(*f)))
            .collect();
        verify_mod::Check {
            name: "wire-format",
            status: Status::Fail,
            detail: format!(
                "duplicate non-repeated proto field(s): {} — last-wins smuggling",
                names.join(", ")
            ),
        }
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            // Every other C0 control byte — notably ESC (0x1b), which drives
            // ANSI/OSC terminal sequences — becomes \uXXXX, so the output is
            // valid JSON (jq / json.loads safe) and carries no control bytes.
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Render an attacker-influenced string safe to print to a terminal. C0 control
/// bytes (including ESC, which drives ANSI/OSC escape sequences) and DEL are
/// rendered as visible `\xHH` escapes, so a crafted stage name, region label, or
/// backend-supplied id cannot inject terminal control sequences through the
/// verifier's own human-readable output.
fn sanitize_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if (c as u32) < 0x20 || c == '\u{7f}' {
            out.push_str(&format!("\\x{:02x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// --- argument parsing ---

fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    let mut iter = std::env::args().skip(1);
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{}", include_str!("octet-verify-help.txt"));
                std::process::exit(0);
            }
            "--envelope" => args.envelope = true,
            "--json" => args.json = true,
            "--hardware-pubkey" => args.hardware_pubkey = Some(need_value(&mut iter, &a)?),
            "--ed25519-pubkey" => args.ed25519_pubkey = Some(need_value(&mut iter, &a)?),
            "--nullifier-store" => args.nullifier_store = Some(need_value(&mut iter, &a)?),
            "--expect-region" => args.expect_region = Some(need_value(&mut iter, &a)?),
            "--app-attest-config" => args.app_attest_config = Some(need_value(&mut iter, &a)?),
            "--skip-hardware-attestation" => args.skip_hardware_attestation = true,
            "--max-age-seconds" => {
                let v = need_value(&mut iter, &a)?;
                args.max_age_s = Some(v.parse().map_err(|e| format!("bad --max-age-seconds: {e}"))?);
            }
            s if s.starts_with("--") => return Err(format!("unknown flag: {s}")),
            _ => {
                if args.path.is_some() {
                    return Err(format!("unexpected extra argument: {a}"));
                }
                args.path = Some(a);
            }
        }
    }
    Ok(args)
}

fn need_value(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    iter.next().ok_or_else(|| format!("{flag} requires a value"))
}

// ===========================================================================
// Backend fetch mode (subcommands: fetch / watch / range)
//
// Trust boundary: the backend is untrusted. These subcommands fetch *bytes*
// and run the exact same local verification pipeline as a local file — no
// backend-supplied field ever contributes to a verdict. See
// VERIFICATION-SPEC.md "Backend fetch mode".
// ===========================================================================

/// Without the `net` feature the backend client is not compiled in: fail loud
/// with a build hint rather than silently doing nothing.
#[cfg(not(feature = "net"))]
fn backend_dispatch(_argv: &[String]) -> ExitCode {
    eprintln!(
        "error: the `fetch`, `watch`, and `range` subcommands require a build with the \
         `net` feature.\n\n    cargo build --features net\n\n\
         The default build is the lean, offline, publicly-auditable verifier and \
         pulls no networking or JSON dependencies."
    );
    ExitCode::from(2)
}

#[cfg(feature = "net")]
fn backend_dispatch(argv: &[String]) -> ExitCode {
    match backend::run(argv) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

#[cfg(feature = "net")]
mod backend {
    use std::collections::HashMap;
    use std::process::ExitCode;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use anyhow::{anyhow, bail, Result};
    use octet_verify::backend::{Backend, Envelope};
    use octet_verify::crypto::{canonical_sig, sha256, SigEncoding};
    use octet_verify::navigate::LocationProof;
    use octet_verify::prost::Message;
    use octet_verify::verify::{verify, Check, Report, Status, VerifyOptions};

    use super::{headline, json_escape, sanitize_terminal, to_hex, DEFAULT_MAX_AGE_S};

    const DEFAULT_WATCH_INTERVAL_S: u64 = 5;

    enum Sub {
        Fetch { proof_id: String },
        Watch,
        Range,
    }

    struct Args {
        sub: Sub,
        backend: String,
        token: String,
        seen_store: Option<String>,
        hardware_pubkey: Option<String>,
        expect_region: Option<String>,
        max_age_s: Option<i64>,
        json: bool,
        interval_s: u64,
        since: Option<String>,
        until: Option<String>,
        app_attest_config: Option<String>,
        skip_hardware_attestation: bool,
    }

    pub fn run(argv: &[String]) -> Result<ExitCode> {
        let args = parse(argv)?;
        let mut backend = Backend::connect(&args.backend, &args.token)?;
        let mut seen = SeenStore::load(args.seen_store.clone())?;

        match args.sub {
            Sub::Fetch { ref proof_id } => {
                let env = backend.fetch_one(proof_id)?;
                let report = verify_envelope(&mut seen, &env, &args)?;
                emit(&env, &report, args.json);
                Ok(verdict_exit(&report))
            }
            Sub::Range => run_range(&mut backend, &mut seen, &args),
            Sub::Watch => run_watch(&mut backend, &mut seen, &args),
        }
    }

    fn run_range(backend: &mut Backend, seen: &mut SeenStore, args: &Args) -> Result<ExitCode> {
        let envs = backend.fetch_range(args.since.as_deref(), args.until.as_deref())?;
        let mut total = 0usize;
        let mut invalid = 0usize;
        let mut inconclusive = 0usize;
        for env in &envs {
            let report = verify_envelope(seen, env, args)?;
            if !report.is_valid() {
                invalid += 1; // a check actively failed (incl. refetch-consistency)
            } else if !report.sigs_verified() {
                inconclusive += 1; // structure ok, signatures never verified
            }
            total += 1;
            emit(env, &report, args.json);
        }
        if !args.json {
            let authentic = total - invalid - inconclusive;
            println!(
                "\n{total} proof(s) · {authentic} authentic · {inconclusive} inconclusive · {invalid} invalid"
            );
        }
        // Worst-state aggregate exit: any INVALID → 1, else any INCONCLUSIVE → 3,
        // else 0. INCONCLUSIVE never collapses into success.
        Ok(if invalid > 0 {
            ExitCode::from(1)
        } else if inconclusive > 0 {
            ExitCode::from(3)
        } else {
            ExitCode::SUCCESS
        })
    }

    fn run_watch(backend: &mut Backend, seen: &mut SeenStore, args: &Args) -> Result<ExitCode> {
        // Long-running live audit. Polls /latest, verifies each *new* proof
        // once, and prints it as it arrives. A repeated proof with identical
        // bytes is skipped; a repeated id with *different* bytes is surfaced as
        // a refetch-consistency FAIL. Ctrl-C stops the loop gracefully and the
        // process exits with the most recent proof's tri-state code (0 authentic
        // / 3 inconclusive / 1 invalid).
        let stop = Arc::new(AtomicBool::new(false));
        let stop_handler = stop.clone();
        ctrlc::set_handler(move || stop_handler.store(true, Ordering::SeqCst))
            .map_err(|e| anyhow!("installing Ctrl-C handler: {e}"))?;

        if !args.json {
            eprintln!(
                "watching {} every {}s — Ctrl-C to stop",
                args.backend, args.interval_s
            );
        }

        // No proofs seen yet → success. Updated to the tri-state code of every
        // verified proof; INCONCLUSIVE never collapses into success.
        let mut last_exit = ExitCode::SUCCESS;
        while !stop.load(Ordering::SeqCst) {
            if let Some(env) = backend.fetch_latest()? {
                let bytes = env.proof_bytes()?;
                let hash = canonical_proof_hash(&bytes);
                // Re-print only when the bytes are new or have changed; an
                // identical re-fetch of the same id is the steady state.
                if !matches!(seen.peek(&env.proof_id, &hash), Seen::Same) {
                    let report = verify_envelope(seen, &env, args)?;
                    last_exit = super::exit_code(&report);
                    emit(&env, &report, args.json);
                }
            }
            sleep_interruptible(&stop, args.interval_s);
        }

        if !args.json {
            eprintln!("stopped.");
        }
        Ok(last_exit)
    }

    /// Sleep up to `secs`, waking early if the stop flag is set, so Ctrl-C is
    /// responsive even with a long `--interval`.
    fn sleep_interruptible(stop: &AtomicBool, secs: u64) {
        let mut remaining_ms = secs.saturating_mul(1000);
        while remaining_ms > 0 && !stop.load(Ordering::SeqCst) {
            let chunk = remaining_ms.min(200);
            std::thread::sleep(Duration::from_millis(chunk));
            remaining_ms -= chunk;
        }
    }

    /// Decode + verify one fetched envelope, then append the refetch-consistency
    /// check (invariant 4). The backend metadata on `env` is never consulted.
    fn verify_envelope(seen: &mut SeenStore, env: &Envelope, args: &Args) -> Result<Report> {
        let bytes = env.proof_bytes()?;
        let mut report = verify_bytes(&bytes, args)?;
        // Replay-control binding: bind the `replay_control` values the
        // (untrusted) backend echoed to what the proof actually signed. The proof
        // already decoded inside verify_bytes, so this re-decode always succeeds.
        if let Ok(proof) = LocationProof::decode(&*bytes) {
            report.checks.push(octet_verify::replay::check_replay_binding(
                &proof,
                env.replay_control().as_ref(),
            ));
        }
        let hash = canonical_proof_hash(&bytes);
        report.checks.push(consistency_check(seen.record(&env.proof_id, &hash)));
        Ok(report)
    }

    /// Run the standard local pipeline over raw proof bytes. This mirrors the
    /// local-file path's key resolution deliberately — the existing `run()` is
    /// left untouched per the repo's change constraints — but feeds the bytes
    /// the backend returned. No transport/envelope signature applies here: the
    /// uploaded payload is a bare `octet.proof.LocationProof`.
    fn verify_bytes(proof_bytes: &[u8], args: &Args) -> Result<Report> {
        let proof = LocationProof::decode(proof_bytes)
            .map_err(|e| anyhow!("failed to decode LocationProof: {e}"))?;

        let (hw_key, hw_source) =
            super::resolve_hardware_key(&proof, args.hardware_pubkey.as_deref())?;

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        let opts = VerifyOptions {
            now_ms,
            max_age_s: args.max_age_s.unwrap_or(DEFAULT_MAX_AGE_S),
            hardware_pubkey: hw_key.as_ref(),
            hw_key_source: &hw_source,
            expect_region: args.expect_region.as_deref(),
        };
        let mut report = verify(&proof, &opts);
        // Same wire-format guard as the local path: fetched bytes are untrusted.
        report.checks.push(super::wire_check(proof_bytes));

        // Offline hardware-attestation layer (feature `appattest`), mirroring the
        // local-file path — a backend-fetched Android proof carries the same
        // certificate chain, so attestation-root + field-2 device-sig apply here.
        if !args.skip_hardware_attestation {
            #[cfg(feature = "appattest")]
            if let Some(cfg_path) = &args.app_attest_config {
                report.checks.push(super::appattest_from_config(&proof, cfg_path)?);
            }
            #[cfg(feature = "appattest")]
            {
                let now_unix_secs = (now_ms / 1000).max(0) as u64;
                report
                    .checks
                    .push(octet_verify::appattest_layer::attestation_root_check(
                        &proof,
                        now_unix_secs,
                    ));
                let pubkey_sec1 = hw_key.as_ref().map(|vk| vk.to_sec1_bytes());
                report
                    .checks
                    .push(octet_verify::appattest_layer::device_signature_check(
                        &proof,
                        pubkey_sec1.as_deref(),
                    ));
            }
        }
        Ok(report)
    }

    fn consistency_check(seen: Seen) -> Check {
        match seen {
            Seen::New => Check {
                name: "refetch-consistency",
                status: Status::Pass,
                detail: "first sighting of this proof_id; byte-hash recorded".into(),
            },
            Seen::Same => Check {
                name: "refetch-consistency",
                status: Status::Pass,
                detail: "bytes identical to a previously-seen fetch of this proof_id".into(),
            },
            Seen::Conflict { prev } => Check {
                name: "refetch-consistency",
                status: Status::Fail,
                detail: format!(
                    "re-fetched bytes differ from a previously-seen fetch of this proof_id \
                     (was sha256 {prev}…); the backend substituted proof bytes — \
                     refetch-consistency invariant violated"
                ),
            },
        }
    }

    // --- seen-store (refetch consistency, invariant 4) ---

    enum Seen {
        New,
        Same,
        Conflict { prev: String },
    }

    /// Maps `proof_id → sha256(proof_bytes)` hex. Always dedups within a single
    /// run; with `--seen-store <file>` it also persists across runs, mirroring
    /// the local path's `--nullifier-store` (newline-delimited "id hash").
    struct SeenStore {
        seen: HashMap<String, String>,
        path: Option<String>,
    }

    impl SeenStore {
        fn load(path: Option<String>) -> Result<Self> {
            let mut seen = HashMap::new();
            if let Some(p) = &path {
                let existing = std::fs::read_to_string(p).unwrap_or_default();
                for line in existing.lines() {
                    let mut it = line.split_whitespace();
                    if let (Some(id), Some(hash)) = (it.next(), it.next()) {
                        seen.insert(id.to_string(), hash.to_string());
                    }
                }
            }
            Ok(SeenStore { seen, path })
        }

        /// Classify without mutating — used by `watch` to decide whether to
        /// re-print an unchanged latest proof.
        fn peek(&self, proof_id: &str, hash: &str) -> Seen {
            match self.seen.get(proof_id) {
                None => Seen::New,
                Some(prev) if prev == hash => Seen::Same,
                Some(prev) => Seen::Conflict { prev: short(prev) },
            }
        }

        /// Classify and record. New ids are appended to the persistent store
        /// (when configured). A conflicting hash is never overwritten — the
        /// first-seen bytes are the reference.
        fn record(&mut self, proof_id: &str, hash: &str) -> Seen {
            match self.seen.get(proof_id) {
                Some(prev) if prev == hash => Seen::Same,
                Some(prev) => Seen::Conflict { prev: short(prev) },
                None => {
                    self.seen.insert(proof_id.to_string(), hash.to_string());
                    if let Some(p) = &self.path {
                        use std::io::Write;
                        if let Ok(mut f) =
                            std::fs::OpenOptions::new().create(true).append(true).open(p)
                        {
                            let _ = writeln!(f, "{proof_id} {hash}");
                        }
                    }
                    Seen::New
                }
            }
        }
    }

    fn short(hash: &str) -> String {
        hash.chars().take(12).collect()
    }

    /// Hash a proof for refetch-consistency / seen-store dedup over a
    /// signature-canonicalized form, so an ECDSA S-malleated twin — byte-distinct
    /// but equally valid — hashes identically and cannot pose as a different
    /// proof. Falls back to the raw bytes if the proof or its platform encoding
    /// doesn't parse (the hash is a dedup aid, never a verification gate; the
    /// verdict is always computed from the original bytes).
    fn canonical_proof_hash(proof_bytes: &[u8]) -> String {
        let canon = (|| -> Option<Vec<u8>> {
            let mut proof = LocationProof::decode(proof_bytes).ok()?;
            let enc = SigEncoding::for_platform(&proof.platform).ok()?;
            for st in &mut proof.stage_attestations {
                st.signature = canonical_sig(&st.signature, enc);
            }
            let mut buf = Vec::new();
            proof.encode(&mut buf).ok()?;
            Some(buf)
        })();
        let bytes = canon.unwrap_or_else(|| proof_bytes.to_vec());
        to_hex(sha256(&bytes).as_slice())
    }

    // --- output ---

    fn verdict_exit(report: &Report) -> ExitCode {
        super::exit_code(report)
    }

    fn emit(env: &Envelope, report: &Report, json: bool) {
        if json {
            println!("{}", report_json_line(env, report));
        } else {
            print_report_human(env, report);
        }
    }

    /// One JSON object per proof, newline-delimited (JSONL) — stream-friendly
    /// for `range`/`watch`. `valid` is authenticity (not rejected AND signatures
    /// verified), `signatures_verified` is the crypto bit, and `verdict` is the
    /// tri-state string — gate automation on `valid`. Backend metadata is echoed
    /// under `backend_meta_untrusted` and contributes nothing to the verdict.
    fn report_json_line(env: &Envelope, report: &Report) -> String {
        let mut out = String::from("{");
        out.push_str(&format!("\"proof_id\":\"{}\",", json_escape(&env.proof_id)));
        out.push_str(&format!("\"verdict\":\"{}\",", headline(report)));
        out.push_str(&format!("\"valid\":{},", report.is_authentic()));
        out.push_str(&format!("\"signatures_verified\":{},", report.sigs_verified()));
        out.push_str("\"checks\":[");
        for (i, c) in report.checks.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"name\":\"{}\",\"status\":\"{}\",\"detail\":\"{}\"}}",
                c.name,
                c.status.tag(),
                json_escape(&c.detail)
            ));
        }
        out.push_str("],");
        out.push_str(&format!(
            "\"backend_meta_untrusted\":{{\"platform\":{},\"created_at\":{}}}",
            opt_json(&env.platform),
            opt_json(&env.created_at)
        ));
        out.push('}');
        out
    }

    fn opt_json(v: &Option<String>) -> String {
        match v {
            Some(s) => format!("\"{}\"", json_escape(s)),
            None => "null".to_string(),
        }
    }

    fn print_report_human(env: &Envelope, report: &Report) {
        // proof_id and the backend metadata are untrusted, attacker-influenced
        // strings — sanitize before they reach the terminal.
        let plat = env.platform.as_deref().unwrap_or("?");
        let created = env.created_at.as_deref().unwrap_or("?");
        let schema = env.proof_schema.as_deref().unwrap_or("?");
        println!("── proof {} ──", sanitize_terminal(&env.proof_id));
        println!(
            "  backend metadata (untrusted): platform={} created_at={} schema={}",
            sanitize_terminal(plat),
            sanitize_terminal(created),
            sanitize_terminal(schema),
        );
        println!("  verdict: {}", headline(report));
        for c in &report.checks {
            println!("    [{:>11}] {:<22} {}", c.status.tag(), c.name, sanitize_terminal(&c.detail));
        }
    }

    // --- argument parsing ---

    fn parse(argv: &[String]) -> Result<Args> {
        let sub_name = argv.first().map(String::as_str).unwrap_or("");
        let mut backend = None;
        let mut token = None;
        let mut seen_store = None;
        let mut hardware_pubkey = None;
        let mut expect_region = None;
        let mut max_age_s = None;
        let mut json = false;
        let mut interval_s = DEFAULT_WATCH_INTERVAL_S;
        let mut since = None;
        let mut until = None;
        let mut app_attest_config = None;
        let mut skip_hardware_attestation = false;
        let mut proof_id: Option<String> = None;

        let mut it = argv.iter().skip(1);
        while let Some(a) = it.next() {
            match a.as_str() {
                "--backend" => backend = Some(need(&mut it, a)?),
                "--token" => token = Some(need(&mut it, a)?),
                "--seen-store" => seen_store = Some(need(&mut it, a)?),
                "--hardware-pubkey" => hardware_pubkey = Some(need(&mut it, a)?),
                "--expect-region" => expect_region = Some(need(&mut it, a)?),
                "--json" => json = true,
                "--max-age-seconds" => {
                    max_age_s = Some(need(&mut it, a)?.parse().map_err(|e| {
                        anyhow!("bad --max-age-seconds: {e}")
                    })?);
                }
                "--interval" => {
                    interval_s = need(&mut it, a)?
                        .parse()
                        .map_err(|e| anyhow!("bad --interval: {e}"))?;
                    if interval_s == 0 {
                        bail!("--interval must be at least 1 second");
                    }
                }
                "--since" => since = Some(need(&mut it, a)?),
                "--until" => until = Some(need(&mut it, a)?),
                "--app-attest-config" => app_attest_config = Some(need(&mut it, a)?),
                "--skip-hardware-attestation" => skip_hardware_attestation = true,
                s if s.starts_with("--") => bail!("unknown flag: {s}"),
                _ => {
                    if proof_id.is_some() {
                        bail!("unexpected extra argument: {a}");
                    }
                    proof_id = Some(a.clone());
                }
            }
        }

        let backend = backend.ok_or_else(|| anyhow!("--backend <url> is required"))?;
        let token = token.ok_or_else(|| anyhow!("--token <activation_bearer> is required"))?;

        let sub = match sub_name {
            "fetch" => Sub::Fetch {
                proof_id: proof_id
                    .ok_or_else(|| anyhow!("fetch requires a <proof-id> argument"))?,
            },
            "watch" => {
                if proof_id.is_some() {
                    bail!("watch takes no positional argument");
                }
                Sub::Watch
            }
            "range" => {
                if proof_id.is_some() {
                    bail!("range takes no positional argument (use --since / --until)");
                }
                Sub::Range
            }
            other => bail!("unknown subcommand: {other}"),
        };

        Ok(Args {
            sub,
            backend,
            token,
            seen_store,
            hardware_pubkey,
            expect_region,
            max_age_s,
            json,
            interval_s,
            since,
            until,
            app_attest_config,
            skip_hardware_attestation,
        })
    }

    fn need<'a>(it: &mut impl Iterator<Item = &'a String>, flag: &str) -> Result<String> {
        it.next()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("{flag} requires a value"))
    }
}

#[cfg(test)]
mod tests {
    use super::{json_escape, sanitize_terminal, wire_check};
    use octet_verify::verify::Status;

    /// Attacker-controlled strings (stage names, region labels, backend ids)
    /// flow into `detail` and the JSON output. ESC (0x1b) drives ANSI/OSC
    /// terminal sequences and raw control bytes break strict JSON parsers; both
    /// must be escaped, never passed through.
    #[test]
    fn json_escape_neutralizes_control_and_ansi_bytes() {
        let nasty = "ok\u{1b}]0;pwned\u{07}\n\t\"q";
        let e = json_escape(nasty);
        assert!(!e.chars().any(|c| (c as u32) < 0x20), "no raw control byte survives");
        assert!(e.contains("\\u001b"), "ESC escaped as \\u001b");
        assert!(e.contains("\\u0007"), "BEL escaped as \\u0007");
        assert!(e.contains("\\n") && e.contains("\\t") && e.contains("\\\""));
    }

    /// Human output goes straight to a terminal, so it is the primary
    /// terminal-injection surface: control bytes must be rendered visible.
    #[test]
    fn sanitize_terminal_renders_escape_bytes_visible() {
        let s = sanitize_terminal("region\u{1b}[31mRED\u{7f}");
        assert!(!s.contains('\u{1b}'), "ESC must not reach the terminal");
        assert!(s.contains("\\x1b"));
        assert!(s.contains("\\x7f"), "DEL escaped too");
    }

    /// The intent of the wire-format guard: a smuggled duplicate of a
    /// non-repeated field produces a FAIL check (→ proof INVALID), while a clean
    /// proof and a legitimately-repeated field (stage_attestations, field 10)
    /// produce PASS.
    #[test]
    fn wire_check_fails_on_duplicate_singular_field_only() {
        // duplicate timestamp_ms (field 7) → Fail, names the field.
        let dup = wire_check(&[0x38, 0x01, 0x38, 0x02]);
        assert_eq!(dup.status, Status::Fail);
        assert!(dup.detail.contains("timestamp_ms"));

        // clean single field → Pass.
        assert_eq!(wire_check(&[0x38, 0x01]).status, Status::Pass);

        // repeated stage_attestations (field 10) → Pass (not a singular field).
        assert_eq!(wire_check(&[0x52, 0x00, 0x52, 0x00]).status, Status::Pass);
    }
}
