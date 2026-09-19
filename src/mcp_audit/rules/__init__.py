"""Importing this package registers every built-in rule."""

from . import (annotations, composition, credentials, drift, environment,  # noqa: F401
               execution,
               poisoning, presentation, transport)
from .base import AuditContext, Rule, all_rules, get_rule, run_rules, rule
from .poisoning import classifier_targets, scan_untrusted_text

__all__ = ["AuditContext", "Rule", "all_rules", "classifier_targets", "get_rule",
           "run_rules", "rule", "scan_untrusted_text"]
