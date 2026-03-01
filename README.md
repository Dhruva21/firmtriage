# firmtriage
Light weight static triage tool that produces a structured risk report for a fw img

# Problem Statement
- firmware images are often large, opaque binary blobs
- security engineers need a fast way to triage them
- manual reverse engineering is time consuming
- hidden risks including:
    - embedded secrets
    - hard-coded certificates
    - weak binary protections
    - suspicious entropy patterns
    - potentially unsigned content

# Goal
Build a light-weight static triage tool that produces a structured riks report from a fw img

# Scope
## v1
- compute file metadata
- calculate entropy source 
- extract strings and scan for
    - URLs
    - IP addresses
    - PEM certificates
    - possible secrets
- Generated structured json report

## v2 (Next)
- full reverse engineering
- disassembly
- dynamic analysis
- fuzzing

# Architecture


# Design philosophy
- Each module must be independent
- each module returns structured findings
- scanner aggregates results
- report layer formats output
- no detection logic in CLI