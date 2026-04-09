# Sentinel v3 Session Summary

## 1. Initial State

At the start of this session, Sentinel v3 had the main structural pieces of an autonomous API security engine:

- OpenAPI parsing
- task-driven orchestration
- shared scan context
- deterministic attack modules
- unit, integration, and end-to-end tests

The main weaknesses were in detection credibility rather than syntax or architecture.

Initial problems:

- detection logic was still partly heuristic
- many attacks treated status-code success as equivalent to exploit success
- vulnerability creation did not consistently require proof
- attack results lacked enough execution context for replay and review
- some end-to-end flows depended on weak assumptions rather than verifiable evidence

In practice, this meant the system could compile and run, but it could still produce unreliable findings or findings that were difficult to validate.

## 2. Introduction of Proof Model

The core improvement in this session was the introduction of a proof model based on **baseline vs attack comparison**.

Pattern:

1. make a baseline request under the expected safe or authorized condition
2. make an attack request under a modified condition
3. only report a vulnerability if the attack response proves a real security failure

Why this matters:

- security testing should prove unauthorized access, not just observe a `200`
- a finding is stronger when it shows the difference between expected behavior and exploit behavior
- this reduces false positives from permissive but non-sensitive responses

This proof model was applied first to:

- IDOR
- Broken Authentication

and later extended to:

- BOLA
- BFLA

## 3. Broken Auth Improvements

Broken Authentication detection was upgraded from heuristic access checks to a stricter proof-based model.

Key changes:

- baseline request with valid authentication was added
- attack variants were constrained to:
  - `no_auth`
  - `invalid_token`
  - `reused_token`
- success now requires:
  - attack response status in `[200, 201]`
  - sensitive data in the response
  - a valid baseline response
  - semantic equivalence between attack response and baseline response

Additional hardening:

- baseline validity is enforced with `baseline_response.status_code in [200, 201]`
- proof fields are populated on every result:
  - `request_url`
  - `request_method`
  - `payload`
  - `response_status`
  - `evidence_excerpt`

Effect:

- false positives were reduced by requiring proof that protected data was accessible without valid authentication
- the system no longer treats a success status code alone as meaningful

## 4. BOLA Implementation

BOLA was implemented as an authenticated object-level authorization test using the same proof discipline.

Core logic:

1. use a valid authenticated session
2. make a baseline request for the original object ID
3. make an attack request with a swapped ID
4. report success only when:
   - the attack response status is in `[200, 201]`
   - the attack response contains sensitive data
   - the baseline response exists
   - the attack response is meaningfully different from the baseline response

Implemented behavior:

- concrete path IDs are extracted when present
- ID swap payloads use the form:
  - `id_swap: {original_id} -> {new_id}`
- evidence snippets are extracted around sensitive fields
- vulnerability output includes request and response proof

Why this is stronger:

- the baseline proves what the authenticated user is supposed to access
- the altered ID proves they can access a different object
- response difference proves unauthorized data exposure rather than ordinary success

## 5. BFLA Implementation

BFLA was implemented in two stages.

### Initial flawed approach

The first version used baseline and attack requests that were effectively identical, and the test behavior depended on server-side request order. That made the proof weak and unrealistic.

Problems in the initial approach:

- same request shape for baseline and attack
- server counter determined whether baseline or attack succeeded
- success did not depend on a real privilege-escalation attempt

### Realism fix

BFLA was then corrected to use request variation:

- baseline request:
  - normal user token
  - default headers
- attack request:
  - same token
  - modified header: `X-Role: admin`

Final success condition:

- attack response status in `[200, 201]`
- attack response contains sensitive data
- baseline response exists
- baseline response status in `[401, 403]`

This made BFLA deterministic and removed reliance on call ordering or server counters.

## 6. Response Comparison Improvements

To stabilize proof matching, a semantic comparison helper was introduced:

```python
def _responses_equivalent(a: str, b: str) -> bool:
    try:
        a_json = json.loads(a)
        b_json = json.loads(b)
        return a_json == b_json
    except Exception:
        return a.strip() == b.strip()
```

This was applied to:

- Broken Auth
- BOLA

Why it helps:

- JSON responses that are semantically identical but formatted differently no longer fail comparison
- plain-text fallback still supports non-JSON cases
- this reduces false negatives caused by formatting differences rather than security differences

## 7. Test Improvements

The test suite was improved to match the stronger proof model.

Main changes:

- dedicated end-to-end tests were added for:
  - IDOR
  - Broken Auth
  - BOLA
  - BFLA
- mock servers were made deterministic
- counter-based behavior was removed from BFLA testing
- proof assertions were strengthened to require:
  - vulnerability creation
  - correct attack type
  - `evidence_excerpt`
  - `request_url`

Examples of realism improvements:

- Broken Auth test provides a valid baseline token and verifies attack equivalence
- BFLA test now denies the baseline request and allows the modified attack request through explicit header variation
- BOLA test simulates different authenticated object responses without relying on timing or call order

## 8. Final System State

At the end of this session, Sentinel v3 supports the following attacks with a stronger proof model:

- IDOR
- Broken Auth
- BOLA
- BFLA

Common properties across these attacks:

- deterministic execution
- explicit baseline vs attack reasoning where applicable
- proof-bearing `AttackResult`
- vulnerability creation only when proof fields are present

## 9. Key Engineering Principles Applied

The work in this session followed a consistent set of engineering rules:

- **deterministic execution**
  - attack modules remain explicit and rule-driven
- **proof over heuristics**
  - vulnerability output must be justified by a concrete response difference or equivalence check
- **minimal abstraction**
  - changes stayed inside existing attack modules and tests
- **incremental expansion**
  - one attack class was hardened at a time rather than rewriting the system

## 10. Limitations

The system is materially stronger than its initial state, but several limitations remain.

- BFLA still depends on an input variation assumption
  - the `X-Role: admin` header is a realistic test hook in the mock environment, but real systems will vary
- response comparison is improved but not fully normalized
  - JSON equality helps, but ordering and normalization beyond direct parsing are still limited
- real-world validation is still narrow
  - the strongest proof paths are currently backed by deterministic mock-server scenarios rather than broad production-like targets

These limitations do not invalidate the work done in this session, but they define the next engineering frontier: broader real-target validation without weakening the proof model.
