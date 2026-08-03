"""Runners: the path-specific adapters that produce normalized reports for the scorer.

Only runners are path specific, everything after a Report is shared. The diff runner runs
synthetic patches through audit_diff in process and folds the findings into a Result. The
repository runner is score only, it reads the findings a whole-repository review already wrote and
scores them, since that review is agent driven and runs out of process.
"""
