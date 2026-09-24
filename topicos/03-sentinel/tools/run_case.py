#!/usr/bin/env python3
"""Corre queries multi-tabela (.kql com let/join) contra fixtures de caso.

Para cada rules/<nome>.kql procura tools/fixtures-<nome-em-minusculas-sem-prefixo>.json:
    rules/CASE-04-correlation.kql  ->  tools/fixtures-case04.json
Cada caso traz "tables" (uma lista de linhas por tabela) e o esperado:
"_expected_rows" e "_expected_names" (valores da coluna Name nas linhas devolvidas).

Sai com codigo 1 se algum caso divergir. Biblioteca padrao apenas.

    python tools/run_case.py
"""

import importlib.util
import io
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_evaluator():
    spec = importlib.util.spec_from_file_location('kql_eval', ROOT / 'tools' / 'kql_eval.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture_for(kql_path):
    stem = kql_path.stem.lower()                      # CASE-04-correlation
    key = re.sub(r'[^a-z0-9]', '', stem.split('-correlation')[0])  # case04
    return ROOT / 'tools' / f'fixtures-{key}.json'


def main():
    ev = load_evaluator()
    kqls = sorted((ROOT / 'rules').glob('*.kql'))
    if not kqls:
        print('nenhum .kql em rules/')
        return 1
    failures = total = 0
    for kql_path in kqls:
        query = io.open(kql_path, encoding='utf-8').read()
        fx_path = fixture_for(kql_path)
        print(f"\n=== {kql_path.name}  <-  {fx_path.name}")
        if not fx_path.exists():
            print('    SEM FIXTURES — declarado nao testado')
            continue
        cases = json.load(io.open(fx_path, encoding='utf-8'))
        for case in cases:
            total += 1
            rows = ev.run_multi(query, case['tables'])
            names = sorted(str(r.get('Name')) for r in rows)
            ok = len(rows) == case['_expected_rows'] and names == sorted(case['_expected_names'])
            failures += not ok
            print(f"    {'PASS' if ok else 'FAIL'}  linhas={len(rows)} esperado={case['_expected_rows']}  {case['_case'][:90]}")
            for r in rows:
                print(f"          {r.get('SignInTime')} -> {r.get('RunTime')} -> {r.get('TaskTime')}  {r.get('Name')}  {r.get('DeviceName')} / {r.get('Computer')}  {r.get('TaskName')}")
    print(f"\n{total - failures}/{total} casos PASS")
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
