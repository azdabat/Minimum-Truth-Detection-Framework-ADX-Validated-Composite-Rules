# Detection Engineering Lifecycle & Real-World Adaptation Model

## Operationalising the Minimum Truth Framework in Production Environments

**Author:** Ala Dabat  
**Framework Alignment:** Minimum Truth → Reinforcement → Scoring → Narrative Convergence  
**Purpose:** Define a repeatable lifecycle for deploying, validating, tuning, and governing detection rules in real SOC environments, while preserving behavioural integrity under telemetry and operational constraints.

---

# Core Principle

Adapt the implementation to the telemetry. Never compromise the behavioural truth.

Detection logic must remain anchored in attack reality, while:

- Scoring adapts to noise
- Suppression adapts to environment
- Structure adapts to telemetry availability

---

# Detection Engineering Lifecycle

## 1. Truth Viability Check

Before building or deploying any rule:

- Does the Minimum Truth exist in available telemetry?
- Is it consistently logged?
- Is it timely and reliable?

| Result | Action |
|---|---|
| Truth exists and reliable | Proceed to build |
| Partial visibility | Adjust scoring or downgrade confidence |
| Missing telemetry | Convert to hunt, backlog item, or telemetry gap |

If the truth cannot be observed, the detection cannot exist.

---

## 2. Baseline Noise Profiling

Before tuning, profile the environment.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| summarize
    Count = count(),
    Devices = dcount(DeviceId)
  by InitiatingProcessFileName,
     InitiatingProcessAccountName,
     bin(Timestamp, 1h)
| order by Count desc
```

Noise must be measured, not assumed.

---

## 3. Rule Classification

Not all rules are detections.

| Type | Purpose |
|---|---|
| Detection | High-confidence, alert-generating |
| Context / Enrichment | Supports investigations, no direct alert |
| Primitive / Sensor | Broad signal, feeds hunts or composites |

Do not force primitives into composites. Each rule must serve its intended role.

---

## 4. Scoring Calibration

Detection confidence is not binary.

```kql
let BaseScore = 60;
let Score_EncodedCommand = 25;
let Score_SuspiciousParent = 20;
let Score_UserWritablePath = 15;
let Score_RareExecution = 10;

let Penalty_ManagedLineage = -25;
let Penalty_BurstExecution = -20;

let FinalScore = BaseScore
    + Score_EncodedCommand
    + Score_SuspiciousParent
    + Score_UserWritablePath
    + Score_RareExecution
    + Penalty_ManagedLineage
    + Penalty_BurstExecution;
```

Suppression must never override truth.

---

## 5. FP / TP Tracking

Track per rule:

- Alert volume
- False positives
- True positives
- Investigation time cost
- Analyst feedback

Core question:

> Is this rule worth existing in its current form?

---

## 6. Rule State Management

| State | Meaning |
|---|---|
| Production | Reliable and actionable |
| Tuned | Needs refinement |
| Enrichment | Context-only |
| Primitive | Sensor / hunting |
| Retired | Removed |

Unmanaged rules create SOC decay.

---

## 7. Feedback Loop Into Framework

Production environments will expose:

- Weak truth anchors
- Noisy reinforcement
- Incorrect scoring weights
- Hidden correlation requirements

These refine the framework. They do not invalidate it.

---

# Where the Framework May Break

## 1. Telemetry Gaps

Minimum Truth cannot be observed.

Response:

- Enable telemetry where possible
- Downgrade confidence
- Convert to hunting logic
- Log as telemetry gap

---

## 2. Reinforcement Noise Explosion

Reinforcement overlaps with legitimate operations.

Response:

- Apply scoring penalties
- Model burst execution
- Identify managed lineage
- Avoid hard exclusions

---

## 3. Prevalence Misleading Signal

Rare does not mean malicious.  
Common does not mean safe.

Response:

- Use burst and radius modelling
- Treat prevalence as context
- Never use prevalence as truth

---

## 4. Query Performance Constraints

Correct logic becomes impractical at scale.

Response:

- Pre-summarize before joins
- Use native enrichment
- Split rules into cleaner sensors
- Move correlation to incident layer

---

## 5. Environment-Specific Behaviour

Enterprise tooling may mimic attacker behaviour.

Response:

- Model behaviour contextually
- Apply scoring penalties
- Avoid static allowlists
- Preserve visibility

---

## 6. Telemetry Reliability Issues

Fields may be inconsistent, delayed, or unreliable.

Response:

- Adjust implementation
- Validate assumptions with engineers
- Preserve the behavioural model

---

## 7. Analyst Usability Failure

A detection can be logically correct but operationally unusable.

Response:

- Simplify output
- Provide clear Hunter Directives
- Focus on triage actions
- Make the result explainable in under 60 seconds

---

# Final Architecture Principle

The detection rule is the sensor.  
The incident is the narrative.

Rules detect truth.  
Reinforcement adds confidence.  
Correlation builds the story.  
The SOC acts on the outcome.

---

# Summary

Detection engineering in production is not:

- Writing perfect rules
- Eliminating all noise
- Building monolithic queries

It is:

1. Anchoring truth
2. Modelling behaviour
3. Adapting to telemetry
4. Scoring intelligently
5. Managing lifecycle
6. Preserving operational value

---

# One-Line Philosophy

I do not just write detections. I manage their performance, evolution, and operational value.
