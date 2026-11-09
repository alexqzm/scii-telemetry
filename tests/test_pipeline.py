"""Конвейер полей: отбор event.dataset по источнику правила во всех бэкендах."""

import re

import pytest
from sigma.backends.elasticsearch import ESQLBackend, LuceneBackend
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.backends.splunk import SplunkBackend

from tools.common import load_rule_file, pipeline, rule_files


@pytest.mark.parametrize("backend", [OpensearchLuceneBackend, LuceneBackend, ESQLBackend, SplunkBackend])
def test_dataset_condition_once_per_query(backend):
    for rf in rule_files():
        if rf.correlation:
            continue
        query = backend(processing_pipeline=pipeline()).convert(load_rule_file(rf.path).collection)[0]
        service = rf.base_rules[0].logsource.service
        assert re.findall(r"event\.dataset\W+scii\.(\w+)", query) == [service], (rf.key, query)


def test_foreign_logsource_untouched():
    from sigma.collection import SigmaCollection

    text = """
title: Foreign
status: test
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image: /bin/sh
    condition: selection
level: low
"""
    query = OpensearchLuceneBackend(processing_pipeline=pipeline()).convert(SigmaCollection.from_yaml(text))[0]
    assert "event.dataset" not in query
