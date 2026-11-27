use criterion::{Criterion, black_box, criterion_group, criterion_main};
use r3x_diagnostics::{build_area_path, preview_core_routing};
use r3x_domain::{CoreId, ProfileSource, RoutingRule, RuleAction, RuleMatcher};
use r3x_profiles::parse_import_payload;
use r3x_security::Redactor;
use uuid::Uuid;

fn bench_subscription_parse(c: &mut Criterion) {
    let mut lines = Vec::with_capacity(1000);
    for i in 0..1000 {
        lines.push(format!(
            "vless://11111111-2222-3333-4444-55555555{:04}@198.51.100.{}:443?type=ws&security=tls&sni=edge{i}.example.invalid#Node-{i}",
            i,
            (i % 250) + 1
        ));
    }
    let payload = lines.join("\n").into_bytes();

    c.bench_function("parse_1000_vless_uris", |b| {
        b.iter(|| {
            let res = parse_import_payload(black_box(&payload), ProfileSource::Manual);
            black_box(res)
        });
    });
}

fn bench_secret_redaction(c: &mut Criterion) {
    let input = "Connecting vless://11111111-2222-3333-4444-555555555555@example.com:443 Bearer supersecrettoken123456 password=topsecretpass&token=abcdef0123456789 ".repeat(20);
    c.bench_function("redact_dense_secrets", |b| {
        b.iter(|| {
            let out = Redactor::redact_str(black_box(&input));
            black_box(out)
        });
    });
}

fn bench_chart_path_builder(c: &mut Criterion) {
    let values: Vec<f64> = (0..3600)
        .map(|i| ((i as f64 * 0.05).sin() + 1.0) * 5_000_000.0)
        .collect();
    c.bench_function("build_area_path_3600", |b| {
        b.iter(|| {
            let svg = build_area_path(black_box(&values), 600.0, 180.0, Some(12_000_000.0));
            black_box(svg)
        });
    });
}

fn bench_routing_preview(c: &mut Criterion) {
    let rules: Vec<RoutingRule> = (0..100)
        .map(|i| RoutingRule {
            id: Uuid::new_v4(),
            name: format!("Rule-{i}"),
            enabled: true,
            priority: i,
            group: "Bench".to_owned(),
            matcher: RuleMatcher::DomainSuffix(format!("service{i}.example.invalid")),
            action: if i % 2 == 0 {
                RuleAction::Direct
            } else {
                RuleAction::Proxy
            },
        })
        .collect();

    c.bench_function("preview_routing_100_rules", |b| {
        b.iter(|| {
            let x = preview_core_routing(CoreId::Xray, black_box(&rules));
            let s = preview_core_routing(CoreId::SingBox, black_box(&rules));
            let m = preview_core_routing(CoreId::Mihomo, black_box(&rules));
            black_box((x, s, m))
        });
    });
}

criterion_group!(
    benches,
    bench_subscription_parse,
    bench_secret_redaction,
    bench_chart_path_builder,
    bench_routing_preview
);
criterion_main!(benches);
