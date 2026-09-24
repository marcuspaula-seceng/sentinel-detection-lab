#!/usr/bin/env python3
"""Corre as fixtures SecurityEvent contra as regras Sentinel desta pasta.

Para cada regra em ../rules/*.sentinel.yaml:
  1. a query OFICIAL, contra "_expected"                      -> conta para PASS/FAIL
  2. a mesma query com `contains` trocado por `has`, contra
     "_expected_has_variant"                                  -> so mede a divergencia

Fixtures vivem em tools/fixtures-*.json. Cada fixture declara "_rule" (nome do ficheiro da
regra sem ".sentinel.yaml"); so corre contra essa regra. Sem "_rule", corre contra todas.

Sai com codigo 1 se a regra oficial falhar qualquer fixture.
Nao instala nada: biblioteca padrao + PyYAML (ja usado no Ciclo 3).

    python tools/run_tests.py
"""

import importlib.util
import io
import json
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = ROOT / 'rules'
FIXTURE_FILES = sorted((ROOT / 'tools').glob('fixtures-*.json'))


def load_evaluator():
    spec = importlib.util.spec_from_file_location('kql_eval', ROOT / 'tools' / 'kql_eval.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def has_variant(query):
    return re.sub(r'\bcontains\b', 'has', query)


def main():
    ev = load_evaluator()
    all_fixtures = []
    for path in FIXTURE_FILES:
        # fixtures de caso multi-tabela (run_case.py) tem "tables" e nao "_expected"; ignorar aqui
        all_fixtures += [f for f in json.load(io.open(path, encoding='utf-8')) if '_expected' in f]
    rules = sorted(RULES.glob('*.sentinel.yaml'))
    if not rules:
        print('nenhuma regra encontrada em', RULES)
        return 1

    failures = total = 0
    rule_keys = {p.name[:-len('.sentinel.yaml')] for p in rules}
    # Ciclo 6 Dia 4 (fail-open apanhado em revisao): um "_rule" com gralha nao casava com
    # nenhuma regra e desaparecia em silencio; a regra ficava com 0 fixtures e "passava".
    orphans = sorted({f['_rule'] for f in all_fixtures if '_rule' in f and f['_rule'] not in rule_keys})
    if orphans:
        print(f'FAIL  fixtures com _rule sem regra correspondente: {orphans}')
        failures += len(orphans)
    for rule_path in rules:
        rule = yaml.safe_load(io.open(rule_path, encoding='utf-8'))
        query = rule['query']
        table, _ = ev.run(query, [])
        rule_key = rule_path.name[:-len('.sentinel.yaml')]
        fixtures = [f for f in all_fixtures if f.get('_rule', rule_key) == rule_key]
        total += len(fixtures)
        if not fixtures:
            print(f'\n=== {rule_path.name}\n    FAIL  regra sem nenhuma fixture — nao passa por ausencia de prova')
            failures += 1
            continue

        print(f"\n=== {rule_path.name}  ({len(fixtures)} fixtures)")
        print(f"    {rule['name']}")
        print(f"    severity={rule.get('severity')}  kind={rule.get('kind')}  status={rule.get('status')}  tabela={table}")
        print(f"\n    --- regra OFICIAL (contains) ---")
        tp = tn = fail = 0
        for fx in fixtures:
            got = 'MATCH' if ev.matches(query, fx) else 'NO MATCH'
            exp = fx['_expected']
            verdict = 'PASS' if got == exp else 'FAIL'
            fail += verdict == 'FAIL'
            tp += got == 'MATCH' == exp
            tn += got == 'NO MATCH' == exp
            print(f"    {verdict}  esperado={exp:<9} obtido={got:<9} {fx['_fixture'][:78]}")
        failures += fail
        print(f"    => {tp} TP / {tn} TN / {fail} FAIL em {len(fixtures)} fixtures")

        print(f"\n    --- variante `has` (so medicao; nao conta para PASS/FAIL) ---")
        vq = has_variant(query)
        diverg = 0
        for fx in fixtures:
            got = 'MATCH' if ev.matches(vq, fx) else 'NO MATCH'
            exp_v = fx.get('_expected_has_variant', fx['_expected'])
            same = 'ok  ' if got == exp_v else 'DIFF'
            official = 'MATCH' if ev.matches(query, fx) else 'NO MATCH'
            marker = '  <- diverge da oficial' if got != official else ''
            diverg += got != official
            print(f"    {same}  has={got:<9} oficial={official:<9} {fx['_fixture'][:60]}{marker}")
        print(f"    => a variante `has` diverge da oficial em {diverg} de {len(fixtures)} fixtures")

    print(f"\n{total - failures}/{total} fixtures PASS nas regras oficiais")
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
