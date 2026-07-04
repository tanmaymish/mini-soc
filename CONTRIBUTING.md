# Contributing to Mini SOC

Thanks for your interest in improving Mini SOC! Contributions of all kinds
are welcome — new detection rules, response playbooks, log parsers, docs,
and bug fixes.

## Getting started

```bash
git clone https://github.com/<your-fork>/mini-soc.git
cd mini-soc
pip install -r requirements.txt
python scripts/train_model.py        # builds the baseline ML model
pytest -q                            # should be all green
python -m cli demo                   # see the engine fire end-to-end
```

## Ways to contribute

### Add a detection rule
1. Create `app/detection/rules/your_rule.py` subclassing `BaseRule`.
2. Implement `name`, `description`, `severity`, and `evaluate(event)`.
3. Register it in `app/detection/engine.py`.
4. Add tests in `tests/test_rules.py`.

### Add a response playbook (SOAR)
1. Create `app/response/playbooks/your_playbook.py` subclassing `BasePlaybook`.
2. Set `target_alerts` to the rule names it should react to.
3. Register it in `app/response/engine.py`.

### Add a log parser
Extend `app/ingestion/syslog_parser.py` with a new regex + `_try_*` handler,
and add a fixture line to `sample_logs/`.

## Before you open a PR
- `pytest -q` passes
- `python -m cli scan sample_logs/auth.log` still works
- New behavior has a test
- Never commit secrets (`.env`, real `DATABASE_URL`, tokens)

## Code style
- Python: standard library + the existing dependencies; keep rules pure and
  side-effect free so they're easy to test.
- Match the surrounding style — clear names, short functions, docstrings that
  explain the *attacker behavior* a rule detects.
