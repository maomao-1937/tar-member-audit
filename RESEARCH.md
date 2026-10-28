# Research and scope

## Observed facts

The parent research run supplied these public sources. The implementation worker
did not refresh the network sources; dates/status below reflect those supplied
observations and must not be read as current vulnerability claims.

- [NousResearch/hermes-agent issue 23794](https://github.com/NousResearch/hermes-agent/issues/23794)
  contains a historical May report involving rollback archive link/member
  handling. It motivates checking member metadata; it does not establish that
  current upstream code remains affected.
- [morluto/rea issue 5745](https://github.com/morluto/rea/issues/5745) was observed
  as CLOSED, with duplicate replacement classified as a gap in the October 21
  report. Its state is not evidence that any current release is vulnerable.
- [Python 3.11 tarfile documentation](https://docs.python.org/3.11/library/tarfile.html)
  describes metadata iteration, archive member types, and extraction interfaces.
  Local Python 3.11.15 source inspection confirmed that ordinary directory paths
  and PAX paths can have trailing slashes trimmed. This utility preserves their
  effective spelling for its stricter namespace checks.

## Inference and distinct purpose

Duplicate names, file-prefix collisions and portable aliases can be worth
reviewing even when no extraction is planned. A metadata-only report can expose
these situations without writing archive member paths. This is the project's
design inference, not a claim of demonstrated adoption or superior security.

The code and synthetic fixtures were written for this project. No competitor or
prior project code was copied. Standard-library parsing hooks are extended only
to retain path spelling, while the standard parser owns metadata interpretation.

## Fair alternatives

- Python's maintained `tarfile` implementation with appropriate extraction
  filters is a better starting point when the actual objective is extraction.
  Check the filter availability and behavior for the installed Python version.
- Maintained system archive tools offer broader format support and established
  interoperability. Their listing modes can provide quick metadata inspection.
- A dedicated filesystem-aware extraction policy can model the destination's
  behavior more closely than this tool's conservative portable namespace policy.

This utility provides indexed namespace findings with no member-path writes.
It neither replaces these alternatives nor evaluates their present security.

## Unknowns and validation boundaries

Only generated fixtures have been validated locally. There is no corpus study,
production adoption, upstream exploit reproduction, throughput benchmark, or
comprehensive cross-extractor compatibility evidence. Real archive producers may
emit PAX extensions deliberately rejected by this narrow profile. Unicode case
folding/NFC is an approximation of portable naming, not an exact implementation
of Windows/macOS filesystem equivalence. Network issue status can change.
The bounds are explicit parser workload caps, not a process resource sandbox.
