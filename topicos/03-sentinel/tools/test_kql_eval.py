#!/usr/bin/env python3
"""Testes do avaliador — Ciclo 6 (Python Security) · Dia 1.

Regra dos testes deste ficheiro: cada um falha por UM motivo, nomeado no proprio nome.
Quando um teste passa, nao prova que o avaliador e o Kusto; prova que o avaliador faz o
que o DAY-0x correspondente afirma. Os casos vem dos achados dos Dias 2-7.1 do Ciclo 5.

    python -m unittest discover -s tools -p "test_*.py" -v
"""

import importlib.util
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('kql_eval', HERE / 'kql_eval.py')
ev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ev)


def one(query, row):
    return ev.matches(query, row)


class ContainsVsHas(unittest.TestCase):
    """Dia 2: substring vs termo. As duas fixtures de divergencia, agora como testes."""

    def test_contains_fails_on_double_space_has_matches(self):
        q = 'T\n| where CommandLine {op} " /ru SYSTEM"'
        row = {'CommandLine': 'schtasks /create /ru  SYSTEM'}
        self.assertFalse(one(q.format(op='contains'), row))
        self.assertTrue(one(q.format(op='has'), row))

    def test_has_matches_terms_inside_a_path_contains_does_not(self):
        q = 'T\n| where CommandLine {op} " /ru SYSTEM"'
        row = {'CommandLine': r'schtasks /tr C:\ru\SYSTEM\x.cmd /ru LAB\u1'}
        self.assertFalse(one(q.format(op='contains'), row))
        self.assertTrue(one(q.format(op='has'), row))

    def test_string_operators_are_case_insensitive_but_equals_is_not(self):
        row = {'F': 'SCHTASKS.EXE'}
        self.assertTrue(one('T\n| where F endswith "schtasks.exe"', row))
        self.assertTrue(one('T\n| where F =~ "schtasks.exe"', row))
        self.assertFalse(one('T\n| where F == "schtasks.exe"', row))


class NullSemantics(unittest.TestCase):
    """Dia 4: null nunca passa num predicado — nem em ==, nem em !=, nem em !in."""

    def test_null_fails_equals_and_not_equals(self):
        self.assertFalse(one('T\n| where L == "IE"', {'L': None}))
        self.assertFalse(one('T\n| where L != "IE"', {'L': None}))

    def test_null_fails_not_in(self):
        self.assertFalse(one('T\n| where L !in ("IE", "PT")', {'L': None}))

    def test_missing_column_behaves_as_null(self):
        self.assertFalse(one('T\n| where L != "IE"', {}))

    def test_tostring_of_missing_dynamic_field_is_empty_string(self):
        q = 'T\n| extend C = tostring(D.isCompliant)\n| where C != "true"'
        self.assertTrue(one(q, {'D': {}}))          # "" != "true" -> passa (Dia 4, fixture 10)
        self.assertTrue(one(q, {'D': None}))


class ParseStage(unittest.TestCase):
    """Dia 3: parse simples e o escape HTML dentro de EventData."""

    def test_parse_extracts_between_literals(self):
        q = 'T\n| parse E with * \'TaskName">\' TaskName "<" *\n| where TaskName == "\\\\eviltask"'
        self.assertTrue(one(q, {'E': '<Data Name="TaskName">\\eviltask</Data>'}))

    def test_parse_missing_literal_yields_empty_not_error(self):
        q = 'T\n| parse E with * \'TaskName">\' TaskName "<" *\n| where TaskName == ""'
        self.assertTrue(one(q, {'E': 'sem task aqui'}))

    def test_rule_depends_on_html_escape(self):
        q = 'T\n| where E contains "&lt;UserId&gt;S-1-5-18&lt;/UserId&gt;"'
        self.assertTrue(one(q, {'E': '...&lt;UserId&gt;S-1-5-18&lt;/UserId&gt;...'}))
        self.assertFalse(one(q, {'E': '...<UserId>S-1-5-18</UserId>...'}))


class Literals(unittest.TestCase):
    """Dia 1 do Ciclo 6: strings. O bug do unicode_escape e o verbatim com aspas duplas."""

    def test_non_ascii_literal_survives(self):
        # antes da correccao: 'ç' -> 'Ã§' e o teste falhava
        self.assertTrue(one('T\n| where N == "coração"', {'N': 'coração'}))

    def test_verbatim_string_doubled_quote(self):
        self.assertTrue(one('T\n| where C contains @" /ru ""SYSTEM"""', {'C': 'x /ru "SYSTEM" y'}))

    def test_backslash_escape_in_regular_string(self):
        self.assertTrue(one('T\n| where P endswith "\\\\schtasks.exe"', {'P': r'C:\Windows\schtasks.exe'}))


class MultiTable(unittest.TestCase):
    """Dia 7.1: let, join, between, e o ';' dentro de string."""

    Q = '''
    let J = 1h;
    let A = TA | project T0 = TimeGenerated, Name;
    let B = TB | where X contains "a;b" | project T1 = TimeGenerated, Name, Extra;
    A
    | join kind=inner B on Name
    | where T1 between (T0 .. T0 + J)
    '''

    def tables(self, t1='2026-01-01T00:30:00Z', name_b='n', x='zz a;b zz'):
        return {
            'TA': [{'TimeGenerated': '2026-01-01T00:00:00Z', 'Name': 'n'}],
            'TB': [{'TimeGenerated': t1, 'Name': name_b, 'X': x, 'Extra': 1}],
        }

    def test_semicolon_inside_string_is_not_a_statement_boundary(self):
        self.assertEqual(len(ev.run_multi(self.Q, self.tables())), 1)

    def test_between_is_inclusive_and_window_bound(self):
        self.assertEqual(len(ev.run_multi(self.Q, self.tables(t1='2026-01-01T01:00:00Z'))), 1)
        self.assertEqual(len(ev.run_multi(self.Q, self.tables(t1='2026-01-01T01:00:01Z'))), 0)
        self.assertEqual(len(ev.run_multi(self.Q, self.tables(t1='2025-12-31T23:59:59Z'))), 0)

    def test_join_key_mismatch_yields_nothing(self):
        self.assertEqual(len(ev.run_multi(self.Q, self.tables(name_b='other'))), 0)

    def test_join_collision_gets_suffix_1_like_kusto(self):
        row = ev.run_multi(self.Q, self.tables())[0]
        self.assertIn('Name1', row)
        self.assertEqual(row['Extra'], 1)

    def test_windows_seven_digit_fraction_timestamp_parses(self):
        t = ev._parse_time('2021-04-21T13:30:00.5894609Z')
        self.assertEqual(t.microsecond, 589460)


class RefusesInsteadOfPretending(unittest.TestCase):
    """A regra que separa este avaliador de um motor: fora do subconjunto, erro."""

    def test_summarize_raises(self):
        with self.assertRaises(SyntaxError):
            ev.run('T\n| summarize count() by X', [{'X': 1}])

    def test_join_other_than_inner_raises(self):
        with self.assertRaises(SyntaxError):
            ev.run_multi('let B = TB;\nTA\n| join kind=leftouter B on X', {'TA': [], 'TB': []})

    def test_unknown_source_raises(self):
        with self.assertRaises(SyntaxError):
            ev.run_multi('Nope\n| where X == 1', {'TA': []})

    def test_leftover_tokens_raise(self):
        with self.assertRaises(SyntaxError):
            ev.run('T\n| where X == 1 2', [{'X': 1}])


if __name__ == '__main__':
    unittest.main()
