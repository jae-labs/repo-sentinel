"""Validate normalized scanner reports at the artifact boundary."""

from __future__ import annotations

from typing import Any, Literal, NotRequired, TypedDict, cast

CoverageStatus = Literal['completed', 'partial', 'incomplete', 'no packages', 'not applicable']
EXPECTED_SCANNERS = {'OSV-Scanner', 'Bandit', 'Hadolint'}
VALID_COVERAGE = {'completed', 'partial', 'incomplete', 'no packages', 'not applicable'}


class Coverage(TypedDict):
    scanner: str
    status: CoverageStatus
    detail: str
    transitive_resolution: NotRequired[bool]


class Finding(TypedDict):
    rule: str
    path: str
    severity: str
    scanner: NotRequired[str]
    line: NotRequired[int | None]
    description: NotRequired[str]
    package: NotRequired[str]
    ecosystem: NotRequired[str]
    version: NotRequired[str]
    aliases: NotRequired[list[str]]
    fixed: NotRequired[list[str]]
    url: NotRequired[str]


class SpecializedReport(TypedDict):
    scanner: Literal['specialized']
    coverage: list[Coverage]
    findings: list[Finding]


class SemgrepReport(TypedDict):
    scanner: Literal['semgrep']
    findings: list[Finding]
    errors: int
    scanned_files: NotRequired[int | None]
    skipped_files: NotRequired[int | None]
    skipped_rules: NotRequired[int | None]


def valid_findings(items: object) -> bool:
    return isinstance(items, list) and all(
        isinstance(item, dict)
        and all(isinstance(item.get(field), str) for field in ('rule', 'severity', 'path'))
        and all(
            key not in item or isinstance(item[key], str)
            for key in ('scanner', 'description', 'package', 'ecosystem', 'version', 'url')
        )
        and (item.get('line') is None or type(item['line']) is int)
        and all(
            key not in item or isinstance(item[key], list) and all(isinstance(value, str) for value in item[key])
            for key in ('aliases', 'fixed')
        )
        for item in items
    )


def parse_specialized(report: dict[str, Any]) -> SpecializedReport | None:
    coverage = report.get('coverage')
    if report.get('scanner') != 'specialized' or not valid_findings(report.get('findings')):
        return None
    if not isinstance(coverage, list) or not all(
        isinstance(entry, dict)
        and isinstance(entry.get('scanner'), str)
        and isinstance(entry.get('status'), str)
        and entry['status'] in VALID_COVERAGE
        and isinstance(entry.get('detail'), str)
        and ('transitive_resolution' not in entry or isinstance(entry['transitive_resolution'], bool))
        for entry in coverage
    ):
        return None
    if len(coverage) != len(EXPECTED_SCANNERS) or {entry['scanner'] for entry in coverage} != EXPECTED_SCANNERS:
        return None
    return cast(SpecializedReport, report)


def parse_semgrep(report: dict[str, Any]) -> SemgrepReport | None:
    if report.get('scanner') != 'semgrep' or not valid_findings(report.get('findings')):
        return None
    for key in ('errors', 'scanned_files', 'skipped_files', 'skipped_rules'):
        count = report.get(key)
        if (key == 'errors' or count is not None) and (type(count) is not int or count < 0):
            return None
    return cast(SemgrepReport, report)


def valid_trivy_report(report: dict[str, Any]) -> bool:
    results = report.get('Results', [])
    if report.get('SchemaVersion') != 2 or not isinstance(results, list):
        return False
    for result in results:
        if not isinstance(result, dict):
            return False
        for key in ('Vulnerabilities', 'Misconfigurations'):
            rows = result.get(key, [])
            if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
                return False
    return True
