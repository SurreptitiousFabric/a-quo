# Omarchy outcome wire fixtures

These manually reviewed raw JSON fixtures freeze the public wire vocabulary for
the typed Omarchy inspection and lifecycle outcomes. The inspection, install,
and update fixtures preserve their pre-refactor field names and string values.

The uninstall fixture defines the deliberately versioned
`urn:a-quo:omarchy-uninstall-outcome:v1` schema. It replaces the ambiguous
`observed_reference_state` compound string with a structured observation whose
state and timing boundary cannot contradict a successful uninstall outcome.
Legacy unversioned uninstall JSON is rejected instead of being silently
reinterpreted.

The fixtures establish serialization compatibility and fail-closed parsing.
They do not establish that the recorded filesystem, Omarchy, consent,
behavioural-analysis, or runtime observations are true.
