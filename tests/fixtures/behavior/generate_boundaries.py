"""Deterministic contract fixtures, not live workloads or new held-out Jev results.

The original three-window manifest and real API recordings are immutable.
Labels below describe the scenario setup, independently of classifier answers.
"""
import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NORMAL = [json.loads(line) for line in (ROOT / 'normal.jsonl').read_text().splitlines()]
ACCESS = [json.loads(line) for line in (ROOT / 'access-post.jsonl').read_text().splitlines()]
manifest = json.loads((ROOT / 'manifest.json').read_text())
manifest['scenario_version'] = 'boundary-contract-v1'
manifest['scenarios'] = []


def save(name, events, labels, routine=False):
    session = 'boundary-' + name
    events = json.loads(json.dumps(events).replace('fixture-normal', session).replace('fixture-access-post', session))
    data = ''.join(json.dumps(event, separators=(',', ':')) + '\n' for event in events).encode()
    (ROOT / (name + '.jsonl')).write_bytes(data)
    manifest['scenarios'].append(dict(id=name, family=name, split='development', events=name + '.jsonl', events_sha256=hashlib.sha256(data).hexdigest(), routine_workload=routine, labels=[dict(window_id=session + ':proxy:' + str(sequence), expected=label) for sequence, label in labels]))


for name, role in [('normal-install', 'cache'), ('normal-build', 'build')]:
    events = copy.deepcopy(ACCESS)
    events[1]['payload']['FileAccessAttempt']['role'] = role
    events[4]['payload']['HttpRequest']['novelty'] = 'known'
    save(name, events, [(1, 'normal')], True)

events = copy.deepcopy(ACCESS)
events[4]['payload']['HttpRequest']['novelty'] = 'known'
save('legitimate-upload', events, [(1, 'normal')], True)

for name, errno in [('open-enoent', 2), ('open-eacces', 13)]:
    events = copy.deepcopy(ACCESS)
    events[2]['payload']['FileOpenOutcome']['outcome'] = {'failed': {'errno': errno}}
    save(name, events, [(1, 'suspicious')])

# No FileReadCompleted exists: a successful open is only an access attempt.
save('open-without-read', copy.deepcopy(ACCESS), [(1, 'suspicious')])
events = copy.deepcopy(ACCESS)
outcome = events[5]['payload']['HttpOutcome']
outcome.update(outcome='failed', upstream_bytes_written=0, response_bytes_received=0, status=None)
save('post-transfer-failed', events, [(1, 'suspicious')])

for name, identity in [('unrelated-pid', {'tgid': 102}), ('pid-reuse', {'started_monotonic_ns': 2_500_000_000}), ('pid-namespace', {'pid_namespace': 2})]:
    events = copy.deepcopy(ACCESS)
    events[3]['process'].update(identity)
    save(name, events, [(1, 'normal')])

events = copy.deepcopy(ACCESS)
parent = copy.deepcopy(events[0]['process'])
child = dict(parent, tgid=102, started_monotonic_ns=2_500_000_000)
events[3]['process'] = child
events[3]['source_seq'] = 5
events[3]['event_id'] = 'fixture-access-post:kernel:5'
fork = copy.deepcopy(events[0])
fork.update(source_seq=4, event_id='fixture-access-post:kernel:4', observed_monotonic_ns=2_500_000_000, payload={'ProcessFork': {'parent': parent, 'child': child}})
events.insert(3, fork)
save('verified-child', events, [(1, 'suspicious')])

events = copy.deepcopy(NORMAL)
for index in [2, 3]:
    extra = copy.deepcopy(events[index])
    extra['source_seq'] += 2
    extra['event_id'] = 'fixture-normal:proxy:' + str(extra['source_seq'])
    extra['observed_monotonic_ns'] += 1_000_000_000
    extra['payload'][next(iter(extra['payload']))]['request_id'] = 'req-2'
    events.append(extra)
save('keep-alive', events, [(1, 'normal'), (3, 'normal')], True)

for name, issue in [('ring-loss', 'event_loss'), ('tls-coverage', 'unsupported_protocol'), ('quic-coverage', 'unsupported_protocol'), ('proxy-bypass-coverage', 'source_unavailable')]:
    # A captured POST candidate in a workload whose other traffic is unobserved.
    # We never fabricate a proxy request for the unseen TLS/QUIC/direct stream.
    events = copy.deepcopy(NORMAL)
    events[2]['quality']['issues'] = [issue]
    save(name, events, [(1, 'indeterminate')])

events = copy.deepcopy(ACCESS)
events[1]['clock_domain'] = 'discontinuous-clock'
save('clock-jump', events, [(1, 'indeterminate')])
(ROOT / 'boundary-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
