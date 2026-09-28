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
    expect_region_type: Option<String>,
    expect_region_contains: Option<(f64, f64)>,
    /// Expected **queried region** (#632): assert the proof's bound `query_region`
    /// equals the reference for this region, so its signed verdict answers
    /// `within(this region)`. Uses the one canonical digest ([`query_region_ref`]).
    /// Specs: `earth`, `country:AT`, `subdivision:US-NY`, `disc:<lat>,<lon>,<r_m>`,
    /// `ellipse:<lat>,<lon>,<semi_major_m>,<semi_minor_m>,<heading_deg>`.
    expect_query_region: Option<String>,
    session_nonce: Option<Vec<u8>>,
    require_session_binding: bool,
    require_schema_v2: bool,
    require_attestation: bool,
    app_attest_config: Option<String>,
    /// Out-of-band App Attest **enrolment bundle** (#67): recovers the attested key
    /// so an assertion-only iOS proof (one carrying no attestation object — the
    /// steady state) can reach `app-attest` PASS via the cached-key path instead of
    /// NOT-CHECKED. Requires `--app-attest-config`. JSON (`v:1`) or proto form.
    app_attest_enrolment_bundle: Option<String>,
    /// Expected Android app identity `(package_name, signing_cert_sha256)` for the
    /// key-attestation `attestationApplicationId` binding (#41 rec: bind the
    /// Android chain to a specific app, not just "some app"). Parsed from
    /// `--android-app-identity <package>,<cert_sha256_hex>`.
    android_app_identity: Option<(String, [u8; 32])>,
    skip_hardware_attestation: bool,
    /// Online Play Integrity (#12, feature `playintegrity`): the first-party
    /// decode endpoint base URL, the verifier's own decode-scoped service token,
    /// and the expected Android package. All three required to run the check;
    /// absent ⇒ `play-integrity` NOT-CHECKED. `integrity_max_age_s` overrides the
    /// token freshness window (defaults to `--max-age-seconds`).
    integrity_decode_url: Option<String>,
    integrity_decode_token: Option<String>,
    integrity_package: Option<String>,
    integrity_max_age_s: Option<i64>,
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
        expect_region_type: args.expect_region_type.as_deref(),
        expect_region_contains: args.expect_region_contains,
        session_nonce: args.session_nonce.as_deref(),
        require_session_binding: args.require_session_binding,
        require_schema_v2: args.require_schema_v2,
        // Cleared for the core call: the CLI appends the attestation checks below
        // and re-applies --require-attestation once, afterward (#41).
        require_attestation: false,
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
            .push(octet_verify::replay::check_replay_binding(&proof, replay_control.as_ref(), args.require_schema_v2));
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
            report.checks.push(appattest_from_config(
                &proof,
                cfg_path,
                args.app_attest_enrolment_bundle.as_deref(),
                hw_key.as_ref().map(|vk| vk.to_sec1_bytes()).as_deref(),
                args.require_attestation,
            )?);
            #[cfg(not(feature = "appattest"))]
            {
                let _ = cfg_path;
                report.checks.push(verify_mod::Check {
                    name: "app-attest",
                    status: Status::NotChecked,
                    detail: "--app-attest-config given but this binary was built without the `appattest` feature".into(),
                });
            }
        } else {
            // No --app-attest-config: still surface `app-attest` as NOT-CHECKED so
            // it is never silently *absent* on an `appattest` build (#41 rec #4) —
            // an iOS proof otherwise shows no app-attest line at all here. A
            // default build has no App Attest surface, so this is feature-gated.
            #[cfg(feature = "appattest")]
            report.checks.push(verify_mod::Check {
                name: "app-attest",
                status: Status::NotChecked,
                detail: "no --app-attest-config supplied; App Attest evidence not checked".into(),
            });
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
            let pubkey_sec1 = hw_key.as_ref().map(|vk| vk.to_sec1_bytes());
            // #41: bind the Android chain to the expected app identity when
            // supplied (--android-app-identity), so it attests THIS app, not just
            // "some key from some app". `None` keeps the hardware-root-only check.
            let expected_app = args.android_app_identity.as_ref().map(|(pkg, cert)| {
                octet_verify::appattest_layer::ExpectedAppIdentity {
                    package_name: pkg.clone(),
                    signing_cert_sha256: *cert,
                }
            });
            report
                .checks
                .push(octet_verify::appattest_layer::attestation_root_check(
                    &proof,
                    now_unix_secs,
                    expected_app.as_ref(),
                    pubkey_sec1.as_deref(), // always bind the attested leaf to the signing key (#31)
                ));

            report
                .checks
                .push(octet_verify::appattest_layer::device_signature_check(
                    &proof,
                    pubkey_sec1.as_deref(),
                ));
        }
    }

    // Online Play Integrity (#12, feature `playintegrity`): opt-in networked check
    // against the decode endpoint. A separate signal — it does NOT feed
    // is_attested() (that is hardware-key attestation); a FAIL here rejects the
    // proof, NOT-CHECKED does not.
    #[cfg(feature = "playintegrity")]
    report.checks.extend(play_integrity_from_cfg(
        &proof,
        args.integrity_decode_url.as_deref(),
        args.integrity_decode_token.as_deref(),
        args.integrity_package.as_deref(),
        args.integrity_max_age_s,
        args.max_age_s.unwrap_or(DEFAULT_MAX_AGE_S),
        now_ms,
    ));
    #[cfg(not(feature = "playintegrity"))]
    if args.integrity_decode_url.is_some()
        || args.integrity_decode_token.is_some()
        || args.integrity_package.is_some()
    {
        report.checks.push(verify_mod::Check {
            name: "play-integrity",
            status: Status::NotChecked,
            detail: "--integrity-* given but this binary was built without the `playintegrity` feature".into(),
        });
    }

    // Fail-closed when attestation is required (#41). Enforced here — after all
    // attestation checks are appended and OUTSIDE the `!skip_hardware_attestation`
    // block — so it runs on every build and cannot be bypassed by
    // --skip-hardware-attestation (skip ⇒ no attestation checks ⇒ is_attested()
    // false ⇒ FAIL). The core verify() call above ran with require_attestation
    // cleared (below), so this is the single evaluation point on the CLI path.
    if args.require_attestation {
        let c = verify_mod::require_attestation_check(&report);
        report.checks.push(c);
    }

    // #632: --expect-query-region — assert the proof's bound query region equals the
    // reference for the region the operator names, via the one canonical digest.
    if let Some(spec) = args.expect_query_region.as_deref() {
        report.checks.push(query_region_match_check(spec, &report));
    }

    Ok(report)
}

/// Parse an `--expect-query-region` spec into a `ProofRegion`, whose canonical
/// reference is then taken with [`query_region_ref`]. Mirrors how Magistrate/the
/// engine build a required region: a disc is `ellipse(lat, lon, r, r, +0.0)`,
/// `earth` uses the default 10000 m altitude, codes are uppercased.
fn parse_query_region_spec(spec: &str) -> Result<octet_verify::navigate::ProofRegion, String> {
    use octet_verify::navigate::{
        proof_region::Region, CountryRegion, EarthRegion, EllipseRegion, LatLon, ProofRegion,
        SubdivisionRegion,
    };
    let floats = |csv: &str, n: usize| -> Result<Vec<f64>, String> {
        let v: Vec<f64> = csv
            .split(',')
            .map(|x| x.trim().parse::<f64>().map_err(|_| format!("{x:?} is not a number")))
            .collect::<Result<_, _>>()?;
        if v.len() != n {
            return Err(format!("expected {n} comma-separated numbers, got {}", v.len()));
        }
        Ok(v)
    };
    let region = match spec.split_once(':') {
        None if spec.eq_ignore_ascii_case("earth") => {
            Region::Earth(EarthRegion { max_altitude_meters: 10000.0 })
        }
        None => return Err(format!("unknown spec {spec:?} (expected earth / country:… / subdivision:… / disc:… / ellipse:…)")),
        Some(("country", v)) => Region::Country(CountryRegion { iso_code: v.trim().to_uppercase() }),
        Some(("subdivision", v)) => Region::Subdivision(SubdivisionRegion { iso_code: v.trim().to_uppercase() }),
        Some(("disc", v)) => {
            let f = floats(v, 3)?;
            Region::Ellipse(EllipseRegion {
                center: Some(LatLon { latitude: f[0], longitude: f[1] }),
                semi_major_m: f[2], semi_minor_m: f[2], heading_deg: 0.0,
            })
        }
        Some(("ellipse", v)) => {
            let f = floats(v, 5)?;
            Region::Ellipse(EllipseRegion {
                center: Some(LatLon { latitude: f[0], longitude: f[1] }),
                semi_major_m: f[2], semi_minor_m: f[3], heading_deg: f[4],
            })
        }
        Some((kind, _)) => return Err(format!("unknown region kind {kind:?}")),
    };
    Ok(ProofRegion { region: Some(region) })
}

/// Compare the proof's bound `query_region` to the reference for the named region.
fn query_region_match_check(spec: &str, report: &Report) -> verify_mod::Check {
    use octet_verify::verify::query_region_ref;
    const NAME: &str = "query-region-match";
    let want = match parse_query_region_spec(spec) {
        Ok(region) => query_region_ref(&region),
        Err(e) => return verify_mod::Check { name: NAME, status: Status::Fail, detail: format!("--expect-query-region: {e}") },
    };
    match (want, report.query_region()) {
        (None, _) => verify_mod::Check { name: NAME, status: Status::Fail,
            detail: "--expect-query-region: that region has no bound reference (a city is unbound)".into() },
        (Some(w), Some(got)) if &w == got => verify_mod::Check { name: NAME, status: Status::Pass,
            detail: "proof's bound query region matches the expected region; its signed verdict answers within(that region)".into() },
        (Some(_), Some(_)) => verify_mod::Check { name: NAME, status: Status::Fail,
            detail: "proof is bound to a DIFFERENT queried region than expected".into() },
        (Some(_), None) => verify_mod::Check { name: NAME, status: Status::Fail,
            detail: "proof carries no bound query region (v2/v1, a background proof, or a city query)".into() },
    }
}

/// Load the shared App Attest config and verify the proof's evidence against it.
#[cfg(feature = "appattest")]
fn appattest_from_config(
    proof: &octet_verify::navigate::LocationProof,
    cfg_path: &str,
    enrolment_bundle: Option<&str>,
    signing_key_sec1: Option<&[u8]>,
    require_binding: bool,
) -> anyhow::Result<verify_mod::Check> {
    use octet_attest_verify::config::Config;
    use octet_verify::appattest_layer::{appattest_check, Expectation};

    let cfg = Config::from_file(cfg_path)
        .map_err(|e| anyhow::anyhow!("app-attest config: {e}"))?;
    let aa = cfg
        .app_attest
        .ok_or_else(|| anyhow::anyhow!("app-attest config has no [app_attest] section"))?;
    let expect = Expectation::new(&aa.team_id, &aa.bundle_id, aa.environment.into());
    // Cached key: without --app-attest-enrolment-bundle this is a stateless
    // single-proof check (`None`), so an assertion-only proof reports NOT-CHECKED
    // (it needs the attestation object or a cached key). With a bundle (#67) we
    // recover the attested key out of band, so the assertion-only steady state
    // reaches PASS via the cached-key path.
    // #38: the live assertion is bound to the SE signing key (certificate_chain[0])
    // — PreferBound by default, RequireBound under --require-attestation.
    let cached = match enrolment_bundle {
        Some(path) => Some(resolve_enrolment_key(path, &expect)?),
        None => None,
    };
    let (check, _key) =
        appattest_check(proof, &expect, cached.as_ref(), signing_key_sec1, require_binding);
    Ok(check)
}

/// Recover the attested key from an out-of-band App Attest **enrolment bundle**
/// (#67) so an assertion-only proof can be verified via the cached-key path. The
/// bundle is the object-bearing `{key_id, app_attest_attestation,
/// app_attest_assertion, attestation_nonce}` subset the SDK exports; it is
/// deserialized (JSON `v:1` or proto `DeviceAttestation`, sniffed by the leading
/// non-whitespace byte), its attestation object verified to the Apple root against
/// the expected app identity, and its recovered key returned.
///
/// The cached counter is seeded to **0**: a stateless CLI verifies one proof and
/// holds no store, so it does not — and cannot — enforce cross-proof assertion
/// counter monotonicity; that stays the stateful library consumer's job
/// (`verify_attested_cached` + a persisted key). The assertion is still fully
/// bound cryptographically — signature, app identity, and, in the #38 bound form,
/// the Secure-Enclave signing key.
#[cfg(feature = "appattest")]
fn resolve_enrolment_key(
    bundle_path: &str,
    expect: &octet_verify::appattest_layer::Expectation,
) -> anyhow::Result<octet_attest_verify::appattest::AttestedKey> {
    use octet_verify::appattest_layer::{appattest_enroll, bundle_from_json, bundle_from_proto};

    let bytes = std::fs::read(bundle_path)
        .map_err(|e| anyhow::anyhow!("reading enrolment bundle {bundle_path}: {e}"))?;
    // Sniff the format: a JSON bundle starts with '{' after optional whitespace;
    // anything else is treated as proto DeviceAttestation wire bytes.
    let is_json = bytes.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{');
    let da = if is_json {
        bundle_from_json(&bytes)?
    } else {
        bundle_from_proto(&bytes)?
    };
    let mut key = appattest_enroll(&da, expect)?;
    key.last_counter = 0;
    Ok(key)
}

/// Build and run the online Play Integrity check (#12) from the resolved config
/// fields, shared by the local and backend-fetch paths.
///
/// `None` when no `--integrity-*` config is given at all (the check is simply not
/// present). When some but not all of url/token/package are given, returns a
/// NOT-CHECKED so a partial config is loud rather than a silent no-op. Freshness
/// window defaults to the proof's `max_age_s` unless overridden.
#[cfg(feature = "playintegrity")]
fn play_integrity_from_cfg(
    proof: &octet_verify::navigate::LocationProof,
    url: Option<&str>,
    token: Option<&str>,
    package: Option<&str>,
    integrity_max_age_s: Option<i64>,
    default_max_age_s: i64,
    now_ms: i64,
) -> Option<verify_mod::Check> {
    use octet_verify::integrity::{play_integrity_check, IntegrityConfig};
    match (url, token, package) {
        (None, None, None) => None,
        (Some(decode_url), Some(service_token), Some(pkg)) => {
            let max_age_ms = integrity_max_age_s
                .unwrap_or(default_max_age_s)
                .saturating_mul(1000);
            Some(play_integrity_check(
                proof,
                &IntegrityConfig { decode_url, service_token, package: pkg, max_age_ms },
                now_ms,
            ))
        }
        _ => Some(verify_mod::Check {
            name: "play-integrity",
            status: Status::NotChecked,
            detail: "incomplete --integrity-* config (need --integrity-decode-url, \
                     --integrity-decode-token, and --integrity-package)"
                .into(),
        }),
    }
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
        Some(p) => {
            let key = keys::load_hardware_pubkey(&PathBuf::from(p))?;
            // #41 (rec #2): a supplied --hardware-pubkey must AGREE with the key
            // in the proof's own certificate_chain[0] when one is extractable.
            // The attested leaf is the signing key by design (it is what the
            // chain attests and what stage-signatures verify against); allowing an
            // operator to override it with a different key is the bug class the
            // #31 attested-leaf binding only catches after the fact. Refuse the
            // conflict up front — verify against the attested key by omitting the
            // flag.
            if let Some(da) = proof.device_attestation.as_ref() {
                if !da.certificate_chain.is_empty() {
                    if let Ok(chain_key) = keys::hardware_pubkey_from_cert_chain(&da.certificate_chain) {
                        if chain_key != key {
                            anyhow::bail!(
                                "--hardware-pubkey conflicts with certificate_chain[0]: the proof \
                                 carries an attested key and verifying against a different key is \
                                 refused (omit --hardware-pubkey to use the attested key)"
                            );
                        }
                    }
                }
            }
            Ok((Some(key), "--hardware-pubkey".into()))
        }
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

/// JSON value for the signed inside/outside verdict (#26): a quoted string, or
/// `null` when there is no signed verdict. INDETERMINATE stays distinct.
fn location_verdict_json(report: &Report) -> &'static str {
    use octet_verify::verify::SignedLocationVerdict::*;
    match report.location_verdict() {
        Some(Inside) => "\"inside\"",
        Some(Outside) => "\"outside\"",
        Some(Indeterminate) => "\"indeterminate\"",
        None => "null",
    }
}

/// JSON value for the bound queried region (#632): `{"region_type":N,"region_id":"<hex>"}`
/// or `null` when the proof carries no bound query (v2/v1, background, or city).
fn query_region_json(report: &Report) -> String {
    match report.query_region() {
        Some(q) => format!(
            "{{\"region_type\": {}, \"region_id\": \"{}\"}}",
            q.region_type,
            q.region_id.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ),
        None => "null".into(),
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
    // Typed signals so automation needn't string-match `checks`: `attested` is
    // the hardware-attestation bit (#41), `region_asserted` is true only when an
    // operator region expectation was supplied and held (#40), and
    // `semantically_bound` is the tamper-evidence bit for the human-meaningful
    // fields (#32) — false for a v1 city/earth region, whose geometry the v1
    // preimage does not cover, so a consumer reading those fails closed.
    out.push_str(&format!("  \"attested\": {},\n", report.is_attested()));
    out.push_str(&format!("  \"region_asserted\": {},\n", report.region_asserted()));
    out.push_str(&format!("  \"semantically_bound\": {},\n", report.is_semantically_bound()));
    // The device's SIGNED inside/outside verdict (#26), or null when there is no
    // signed verdict (v1 / unbound / UNSPECIFIED). INDETERMINATE is preserved.
    out.push_str(&format!("  \"location_verdict\": {},\n", location_verdict_json(report)));
    // The bound queried region the verdict answers about (#632, v3), or null. A
    // consumer matches `region_id` against its own query_region_ref(R) to read
    // within(R) directly. region_id is hex.
    out.push_str(&format!("  \"query_region\": {},\n", query_region_json(report)));
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
            "--expect-query-region" => args.expect_query_region = Some(need_value(&mut iter, &a)?),
            "--expect-region-type" => {
                let v = need_value(&mut iter, &a)?;
                if !octet_verify::verify::is_known_region_type(&v) {
                    return Err(format!(
                        "--expect-region-type: unknown region type {v:?} (expected one of {:?})",
                        octet_verify::verify::REGION_TYPES
                    ));
                }
                args.expect_region_type = Some(v);
            }
            "--expect-region-contains" => {
                let v = need_value(&mut iter, &a)?;
                args.expect_region_contains = Some(parse_latlon(&v)?);
            }
            "--session-nonce" => {
                let v = need_value(&mut iter, &a)?;
                args.session_nonce = Some(parse_hex_nonce(&v)?);
            }
            "--require-session-binding" => args.require_session_binding = true,
            "--require-schema-v2" => args.require_schema_v2 = true,
            "--require-attestation" => args.require_attestation = true,
            "--app-attest-config" => args.app_attest_config = Some(need_value(&mut iter, &a)?),
            "--integrity-decode-url" => args.integrity_decode_url = Some(need_value(&mut iter, &a)?),
            "--integrity-decode-token" => args.integrity_decode_token = Some(need_value(&mut iter, &a)?),
            "--integrity-package" => args.integrity_package = Some(need_value(&mut iter, &a)?),
            "--integrity-max-age-seconds" => {
                let v = need_value(&mut iter, &a)?;
                args.integrity_max_age_s =
                    Some(v.parse().map_err(|e| format!("bad --integrity-max-age-seconds: {e}"))?);
            }
            "--app-attest-enrolment-bundle" => {
                args.app_attest_enrolment_bundle = Some(need_value(&mut iter, &a)?);
            }
            "--android-app-identity" => {
                let v = need_value(&mut iter, &a)?;
                args.android_app_identity = Some(parse_android_identity(&v)?);
            }
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
    // The enrolment bundle needs the app identity to verify against (#67); the
    // config is the only source of team/bundle, so require it.
    if args.app_attest_enrolment_bundle.is_some() && args.app_attest_config.is_none() {
        return Err("--app-attest-enrolment-bundle requires --app-attest-config".to_string());
    }
    Ok(args)
}

fn need_value(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    iter.next().ok_or_else(|| format!("{flag} requires a value"))
}

/// Decode a hex string (optional `0x`, even length) into raw bytes — the CLI
/// form of `--session-nonce`. The library API (`VerifyOptions.session_nonce`)
/// takes raw bytes directly, which is what a relying party integrating the crate
/// uses; the flag is a convenience for manual verification and testing.
fn parse_hex_nonce(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return Err("--session-nonce must be an even-length hex string".into());
    }
    let nibble = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err("--session-nonce is not valid hex".into()),
        }
    };
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((nibble(b[i])? << 4) | nibble(b[i + 1])?);
        i += 2;
    }
    Ok(out)
}

/// Parse `--expect-region-contains "<lat>,<lon>"` into decimal degrees, with
/// range validation so a transposed or out-of-range point fails loud.
fn parse_latlon(s: &str) -> Result<(f64, f64), String> {
    let (a, b) = s
        .split_once(',')
        .ok_or_else(|| format!("--expect-region-contains: expected \"<lat>,<lon>\", got {s:?}"))?;
    let lat: f64 = a
        .trim()
        .parse()
        .map_err(|_| format!("--expect-region-contains: latitude {:?} is not a number", a.trim()))?;
    let lon: f64 = b
        .trim()
        .parse()
        .map_err(|_| format!("--expect-region-contains: longitude {:?} is not a number", b.trim()))?;
    if !(-90.0..=90.0).contains(&lat) {
        return Err(format!("--expect-region-contains: latitude {lat} out of range [-90, 90]"));
    }
    if !(-180.0..=180.0).contains(&lon) {
        return Err(format!("--expect-region-contains: longitude {lon} out of range [-180, 180]"));
    }
    Ok((lat, lon))
}

/// Parse `--android-app-identity "<package>,<cert_sha256_hex>"` into the expected
/// Android app identity: the package name and the SHA-256 (64 hex chars) of the
/// signing certificate's DER (an `attestationApplicationId` `signatureDigests`
/// entry).
fn parse_android_identity(s: &str) -> Result<(String, [u8; 32]), String> {
    let (pkg, hex) = s.split_once(',').ok_or_else(|| {
        format!("--android-app-identity: expected \"<package>,<cert_sha256_hex>\", got {s:?}")
    })?;
    let pkg = pkg.trim();
    if pkg.is_empty() {
        return Err("--android-app-identity: empty package name".into());
    }
    let hex = hex.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "--android-app-identity: cert sha256 must be 64 hex chars, got {:?}",
            hex
        ));
    }
    let mut cert = [0u8; 32];
    for (i, byte) in cert.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| "--android-app-identity: cert sha256 is not valid hex".to_string())?;
    }
    Ok((pkg.to_string(), cert))
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
    // A dependency panic (an unexpected ureq/url/serde edge) must not abort the
    // process with exit 101 — outside the documented 0/1/2/3 contract (#39). The
    // default panic hook still prints the panic to stderr (fail loud), but we
    // catch the unwind and map it to the usage/IO/backend-error code (2).
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| backend::run(argv))) {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
        Err(_) => {
            eprintln!("error: backend operation panicked (treated as a backend error, exit 2)");
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

    use super::{
        headline, json_escape, location_verdict_json, parse_android_identity, parse_hex_nonce,
        parse_latlon, sanitize_terminal, to_hex, DEFAULT_MAX_AGE_S,
    };

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
        expect_region_type: Option<String>,
        expect_region_contains: Option<(f64, f64)>,
        session_nonce: Option<Vec<u8>>,
        require_session_binding: bool,
        require_schema_v2: bool,
        require_attestation: bool,
        max_age_s: Option<i64>,
        json: bool,
        interval_s: u64,
        since: Option<String>,
        until: Option<String>,
        app_attest_config: Option<String>,
        app_attest_enrolment_bundle: Option<String>,
        android_app_identity: Option<(String, [u8; 32])>,
        skip_hardware_attestation: bool,
        integrity_decode_url: Option<String>,
        integrity_decode_token: Option<String>,
        integrity_package: Option<String>,
        integrity_max_age_s: Option<i64>,
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
        // #39: make a long run of empty polls observable, so a `watch` that is
        // quietly returning nothing (backend has no proofs, or is mis-pointed) is
        // distinguishable from one that is verifying. A transport error already
        // fails loud via `?`; a 404 on /latest is the legitimate "no proofs yet"
        // and keeps polling — but we surface a periodic heartbeat for it.
        const EMPTY_POLL_HEARTBEAT: u64 = 12;
        let mut empty_polls: u64 = 0;
        while !stop.load(Ordering::SeqCst) {
            match backend.fetch_latest()? {
                Some(env) => {
                    empty_polls = 0;
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
                None => {
                    empty_polls += 1;
                    if !args.json && empty_polls % EMPTY_POLL_HEARTBEAT == 0 {
                        eprintln!(
                            "still watching — {empty_polls} polls, no proofs yet for this license \
                             (backend reachable, /v1/proofs/latest returns none)"
                        );
                    }
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
                args.require_schema_v2,
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
            expect_region_type: args.expect_region_type.as_deref(),
            expect_region_contains: args.expect_region_contains,
            session_nonce: args.session_nonce.as_deref(),
            require_session_binding: args.require_session_binding,
            require_schema_v2: args.require_schema_v2,
            // Cleared for the core call; re-applied once after the attestation
            // checks below (#41).
            require_attestation: false,
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
                report.checks.push(super::appattest_from_config(
                    &proof,
                    cfg_path,
                    args.app_attest_enrolment_bundle.as_deref(),
                    hw_key.as_ref().map(|vk| vk.to_sec1_bytes()).as_deref(),
                    args.require_attestation,
                )?);
            }
            #[cfg(feature = "appattest")]
            {
                let now_unix_secs = (now_ms / 1000).max(0) as u64;
                let pubkey_sec1 = hw_key.as_ref().map(|vk| vk.to_sec1_bytes());
                // #41: bind the Android chain to the expected app identity when
                // supplied (--android-app-identity), same as the local-file path.
                let expected_app = args.android_app_identity.as_ref().map(|(pkg, cert)| {
                    octet_verify::appattest_layer::ExpectedAppIdentity {
                        package_name: pkg.clone(),
                        signing_cert_sha256: *cert,
                    }
                });
                report
                    .checks
                    .push(octet_verify::appattest_layer::attestation_root_check(
                        &proof,
                        now_unix_secs,
                        expected_app.as_ref(),
                        pubkey_sec1.as_deref(), // always bind the attested leaf to the signing key (#31)
                    ));
                report
                    .checks
                    .push(octet_verify::appattest_layer::device_signature_check(
                        &proof,
                        pubkey_sec1.as_deref(),
                    ));
            }
        }
        // Online Play Integrity (#12, feature `playintegrity`), mirroring the
        // local-file path — a fetched Android proof carries the same field-4 token.
        #[cfg(feature = "playintegrity")]
        report.checks.extend(super::play_integrity_from_cfg(
            &proof,
            args.integrity_decode_url.as_deref(),
            args.integrity_decode_token.as_deref(),
            args.integrity_package.as_deref(),
            args.integrity_max_age_s,
            args.max_age_s.unwrap_or(DEFAULT_MAX_AGE_S),
            now_ms,
        ));
        #[cfg(not(feature = "playintegrity"))]
        if args.integrity_decode_url.is_some()
            || args.integrity_decode_token.is_some()
            || args.integrity_package.is_some()
        {
            report.checks.push(octet_verify::verify::Check {
                name: "play-integrity",
                status: octet_verify::verify::Status::NotChecked,
                detail: "--integrity-* given but this binary was built without the `playintegrity` feature".into(),
            });
        }

        // Fail-closed when attestation is required (#41) — after the attestation
        // checks and outside the skip block, on every build; the core call above
        // ran with require_attestation cleared, so this is the single evaluation.
        if args.require_attestation {
            let c = octet_verify::verify::require_attestation_check(&report);
            report.checks.push(c);
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
    /// tri-state string — gate automation on `valid`. The typed bits mirror the
    /// local `--json` report (`attested`, `region_asserted`, `semantically_bound`,
    /// `location_verdict`), so automation never string-matches `checks`. Backend
    /// metadata is echoed under `backend_meta_untrusted` and contributes nothing
    /// to the verdict.
    fn report_json_line(env: &Envelope, report: &Report) -> String {
        let mut out = String::from("{");
        out.push_str(&format!("\"proof_id\":\"{}\",", json_escape(&env.proof_id)));
        out.push_str(&format!("\"verdict\":\"{}\",", headline(report)));
        out.push_str(&format!("\"valid\":{},", report.is_authentic()));
        out.push_str(&format!("\"signatures_verified\":{},", report.sigs_verified()));
        out.push_str(&format!("\"attested\":{},", report.is_attested()));
        out.push_str(&format!("\"region_asserted\":{},", report.region_asserted()));
        out.push_str(&format!("\"semantically_bound\":{},", report.is_semantically_bound()));
        out.push_str(&format!("\"location_verdict\":{},", location_verdict_json(report)));
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
        let mut expect_region_type = None;
        let mut expect_region_contains = None;
        let mut session_nonce = None;
        let mut require_session_binding = false;
        let mut require_schema_v2 = false;
        let mut require_attestation = false;
        let mut max_age_s = None;
        let mut json = false;
        let mut interval_s = DEFAULT_WATCH_INTERVAL_S;
        let mut since = None;
        let mut until = None;
        let mut app_attest_config = None;
        let mut integrity_decode_url = None;
        let mut integrity_decode_token = None;
        let mut integrity_package = None;
        let mut integrity_max_age_s = None;
        let mut app_attest_enrolment_bundle = None;
        let mut android_app_identity = None;
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
                "--expect-region-type" => {
                    let v = need(&mut it, a)?;
                    if !octet_verify::verify::is_known_region_type(&v) {
                        anyhow::bail!(
                            "--expect-region-type: unknown region type {v:?} (expected one of {:?})",
                            octet_verify::verify::REGION_TYPES
                        );
                    }
                    expect_region_type = Some(v);
                }
                "--expect-region-contains" => {
                    expect_region_contains = Some(parse_latlon(&need(&mut it, a)?).map_err(|e| anyhow!("{e}"))?);
                }
                "--session-nonce" => {
                    session_nonce = Some(parse_hex_nonce(&need(&mut it, a)?).map_err(|e| anyhow!("{e}"))?);
                }
                "--require-session-binding" => require_session_binding = true,
                "--require-schema-v2" => require_schema_v2 = true,
                "--require-attestation" => require_attestation = true,
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
                "--integrity-decode-url" => integrity_decode_url = Some(need(&mut it, a)?),
                "--integrity-decode-token" => integrity_decode_token = Some(need(&mut it, a)?),
                "--integrity-package" => integrity_package = Some(need(&mut it, a)?),
                "--integrity-max-age-seconds" => {
                    integrity_max_age_s = Some(
                        need(&mut it, a)?
                            .parse()
                            .map_err(|e| anyhow!("bad --integrity-max-age-seconds: {e}"))?,
                    );
                }
                "--app-attest-enrolment-bundle" => {
                    app_attest_enrolment_bundle = Some(need(&mut it, a)?)
                }
                "--android-app-identity" => {
                    android_app_identity =
                        Some(parse_android_identity(&need(&mut it, a)?).map_err(|e| anyhow!("{e}"))?);
                }
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

        // The enrolment bundle needs the app identity from the config to verify
        // against (#67), so require --app-attest-config alongside it.
        if app_attest_enrolment_bundle.is_some() && app_attest_config.is_none() {
            bail!("--app-attest-enrolment-bundle requires --app-attest-config");
        }

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
            expect_region_type,
            expect_region_contains,
            session_nonce,
            require_session_binding,
            require_schema_v2,
            require_attestation,
            max_age_s,
            json,
            interval_s,
            since,
            until,
            app_attest_config,
            app_attest_enrolment_bundle,
            android_app_identity,
            skip_hardware_attestation,
            integrity_decode_url,
            integrity_decode_token,
            integrity_package,
            integrity_max_age_s,
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
    use super::{json_escape, parse_query_region_spec, sanitize_terminal, wire_check};
    use octet_verify::verify::{query_region_ref, Status};

    /// The `--expect-query-region` spec parser maps to the same `ProofRegion` the
    /// SDK/engine bind, so `query_region_ref` of the parsed region equals the
    /// proof's bound `query_region` (#632).
    #[test]
    fn expect_query_region_spec_parses_to_canonical_refs() {
        // country / subdivision → uppercased ISO bytes.
        let c = query_region_ref(&parse_query_region_spec("country:at").unwrap()).unwrap();
        assert_eq!((c.region_type, c.region_id.as_slice()), (2, b"AT".as_slice()));
        let s = query_region_ref(&parse_query_region_spec("subdivision:us-ny").unwrap()).unwrap();
        assert_eq!((s.region_type, s.region_id.as_slice()), (7, b"US-NY".as_slice()));

        // earth → default 10000 m altitude, f64-be.
        let e = query_region_ref(&parse_query_region_spec("earth").unwrap()).unwrap();
        assert_eq!((e.region_type, e.region_id.as_slice()), (1, 10000.0f64.to_be_bytes().as_slice()));

        // disc → ellipse(lat,lon,r,r,+0.0), a 32-byte digest; and the same disc via
        // the explicit ellipse spec gives an identical digest.
        let d = query_region_ref(&parse_query_region_spec("disc:48.2082,16.3738,1500.5").unwrap()).unwrap();
        assert_eq!(d.region_type, 4);
        assert_eq!(d.region_id.len(), 32);
        let el = query_region_ref(&parse_query_region_spec("ellipse:48.2082,16.3738,1500.5,1500.5,0").unwrap()).unwrap();
        assert_eq!(d.region_id, el.region_id, "disc == ellipse(r,r,+0.0)");

        // bad specs error, city is unbound.
        assert!(parse_query_region_spec("nonsense").is_err());
        assert!(parse_query_region_spec("disc:1,2").is_err());
        // city:… parses to a region, but it has no bound reference.
        assert!(parse_query_region_spec("country:").unwrap().region.is_some());
    }

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

    /// `--expect-region-contains` parsing: accepts "lat,lon" (with whitespace),
    /// rejects a missing comma, non-numbers, and out-of-range coordinates.
    #[test]
    fn parse_latlon_accepts_valid_rejects_malformed_and_out_of_range() {
        use super::parse_latlon;
        assert_eq!(parse_latlon("37.7749,-122.4194").unwrap(), (37.7749, -122.4194));
        assert_eq!(parse_latlon("  37.77 , -122.42 ").unwrap(), (37.77, -122.42));
        assert!(parse_latlon("37.77").is_err()); // no comma
        assert!(parse_latlon("north,-122.4").is_err()); // non-number
        assert!(parse_latlon("91.0,0.0").is_err()); // lat out of range
        assert!(parse_latlon("0.0,181.0").is_err()); // lon out of range
    }

    /// `--android-app-identity` parsing (#41): "package,cert_sha256_hex".
    #[test]
    fn parse_android_identity_parses_and_validates() {
        use super::parse_android_identity;
        let hex = "ab".repeat(32); // 64 hex chars
        let (pkg, cert) = parse_android_identity(&format!("com.example.app,{hex}")).unwrap();
        assert_eq!(pkg, "com.example.app");
        assert_eq!(cert, [0xabu8; 32]);
        assert!(parse_android_identity(&format!("  com.x , {hex} ")).is_ok()); // whitespace ok
        assert!(parse_android_identity("com.example.app").is_err()); // no comma
        assert!(parse_android_identity(&format!(",{hex}")).is_err()); // empty package
        assert!(parse_android_identity("com.x,zz").is_err()); // not hex / wrong length
        assert!(parse_android_identity(&format!("com.x,{}", "ab".repeat(31))).is_err()); // 62 chars
    }

    /// #41 (rec #2): a --hardware-pubkey that disagrees with the proof's own
    /// attested certificate_chain[0] is refused — you cannot verify against a key
    /// other than the attested one when the proof carries an attestation.
    #[test]
    fn resolve_hardware_key_rejects_a_conflicting_hardware_pubkey() {
        use octet_verify::navigate::{DeviceAttestation, LocationProof};
        use p256::ecdsa::SigningKey;

        let sec1 = |seed: u8| {
            SigningKey::from_slice(&[seed; 32])
                .unwrap()
                .verifying_key()
                .to_sec1_bytes()
                .to_vec()
        };
        let a = sec1(1);
        let b = sec1(2);
        assert_ne!(a, b);

        let dir = std::env::temp_dir().join("octet-verify-test-resolve-hw");
        std::fs::create_dir_all(&dir).unwrap();
        let a_path = dir.join("a.sec1");
        std::fs::write(&a_path, &a).unwrap();
        let a_path = a_path.to_str().unwrap();

        // certificate_chain[0] = an iOS-style raw SE key (parses as SEC1).
        let proof = |chain0: Vec<u8>| LocationProof {
            device_attestation: Some(DeviceAttestation {
                certificate_chain: vec![chain0],
                ..Default::default()
            }),
            ..Default::default()
        };

        // Flag A vs chain B → conflict (refused).
        let err = super::resolve_hardware_key(&proof(b), Some(a_path)).unwrap_err();
        assert!(err.to_string().contains("conflicts with certificate_chain"), "{err}");

        // Flag A vs chain A → agree, resolves.
        let (key, source) = super::resolve_hardware_key(&proof(a.clone()), Some(a_path)).unwrap();
        assert!(key.is_some());
        assert_eq!(source, "--hardware-pubkey");

        // No chain → flag used, no conflict possible.
        let (key, _) = super::resolve_hardware_key(&LocationProof::default(), Some(a_path)).unwrap();
        assert!(key.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
