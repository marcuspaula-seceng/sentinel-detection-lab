#!/usr/bin/env python3
"""Ponto de entrada unico do laboratorio — Ciclo 6 · Dia 3.

    python tools/lab.py test     fixtures das regras (run_tests)
    python tools/lab.py case     casos multi-tabela (run_case)
    python tools/lab.py lint     linter dos templates (lint_rules)
    python tools/lab.py unit     testes unitarios do avaliador
    python tools/lab.py all      tudo, por esta ordem; para no primeiro que falhar

Codigo de saida: 0 se tudo passou; 1 no primeiro passo que falhou. E o que o CI corre.
Nao instala nada. Nao escreve nada.
"""

import argparse
import importlib.util
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def step_test():
    return _load('run_tests').main()


def step_case():
    return _load('run_case').main()


def step_lint():
    return _load('lint_rules').main()


def step_unit():
    cmd = [sys.executable, '-m', 'unittest', 'discover', '-s', str(HERE), '-p', 'test_*.py']
    return subprocess.call(cmd)


STEPS = {'unit': step_unit, 'lint': step_lint, 'test': step_test, 'case': step_case}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('step', choices=list(STEPS) + ['all'])
    args = ap.parse_args(argv)
    order = list(STEPS) if args.step == 'all' else [args.step]
    for name in order:
        print(f'\n##### {name} #####')
        rc = STEPS[name]()
        if rc:
            print(f'\n##### {name}: FALHOU (rc={rc}) — parado aqui #####')
            return 1
    print('\n##### tudo PASS #####')
    return 0


if __name__ == '__main__':
    sys.exit(main())
