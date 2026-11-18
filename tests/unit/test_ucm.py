"""Unit tests for Universal Code Model (UCM) fact extraction."""

from plumbline.ucm.builder import extract_file_facts
from plumbline.ucm.lexical import extract_lexical_facts

PY_SAMPLE = """
# Setup logger
import os
from datetime import datetime

class AuthManager:
    def authenticate_user(self, username, password):
        api_key = os.environ.get("SECRET_KEY")
        print("Authenticating...")
        try:
            return True
        except Exception:
            pass
"""

JS_SAMPLE = """
// Express handler
import express from 'express';
const path = require('path');

function processRequest(req, res) {
    const token = process.env.API_TOKEN;
    console.log("Processing");
    try {
        validate(token);
    } catch (e) {
    }
}
"""

GO_SAMPLE = """
// Package main
package main

import "os"

func HandlePing() {
    val := os.Getenv("PORT")
    println(val)
}
"""


def test_lexical_extraction_python() -> None:
    facts = extract_lexical_facts("auth.py", "python", PY_SAMPLE)
    assert facts.engine_used == "lexical"

    sym_names = [s.name for s in facts.symbols]
    assert "AuthManager" in sym_names
    assert "authenticate_user" in sym_names

    mod_names = [i.module for i in facts.imports]
    assert "os" in mod_names
    assert "datetime" in mod_names

    assert any(c.text.startswith("Setup logger") for c in facts.comments)
    assert any(e.var_name == "SECRET_KEY" for e in facts.env_reads)
    assert any(h.empty for h in facts.handlers)


def test_lexical_extraction_javascript() -> None:
    facts = extract_lexical_facts("app.js", "javascript", JS_SAMPLE)
    assert facts.engine_used == "lexical"

    sym_names = [s.name for s in facts.symbols]
    assert "processRequest" in sym_names

    mod_names = [i.module for i in facts.imports]
    assert "express" in mod_names
    assert "path" in mod_names

    assert any(e.var_name == "API_TOKEN" for e in facts.env_reads)


def test_lexical_extraction_go() -> None:
    facts = extract_lexical_facts("main.go", "go", GO_SAMPLE)
    assert facts.engine_used == "lexical"

    sym_names = [s.name for s in facts.symbols]
    assert "HandlePing" in sym_names

    assert any(e.var_name == "PORT" for e in facts.env_reads)


def test_builder_extract_facts_fallback_parity() -> None:
    # builder should work on python code (either tree-sitter or lexical)
    facts = extract_file_facts("auth.py", "python", PY_SAMPLE)
    assert facts.engine_used in ("tree-sitter", "lexical")

    # Key facts must be present regardless of engine
    sym_names = [s.name for s in facts.symbols]
    assert "authenticate_user" in sym_names
    assert len(facts.imports) >= 2
    assert len(facts.comments) >= 1
