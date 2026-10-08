# Behavior replay fixtures

These three synthetic metadata traces contain no real credentials and do not invoke a VM or an API. The canary in local path/host fields verifies that correlation and the provider projection remove raw strings. The manifest's all-zero VM digest explicitly denotes synthetic data, not a measured VM image.

`normal.jsonl` is a routine POST without credential access. `access-post.jsonl` contains a credential open attempt and a related POST by a confirmed writer. It establishes an observed association, not successful reading or exfiltration. `event-loss.jsonl` repeats that scenario with an observation gap; classifiers must abstain and evaluation keeps this missed suspicious window in the denominator.

Labels are fixed from the scenario specification before classification. Family names remain in a single development/held-out split. A/B/C/D use identical candidate window IDs. B masks host features deliberately; this is distinct from the real collector loss in the third fixture.

Mock results verify plumbing and arithmetic only. Actual Jev quality must be measured separately with the pinned model, these sanitized projections, and a reviewed evaluation manifest. No performance or quality promotion is inferred from passing fixture tests.
