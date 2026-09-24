#!/usr/bin/env python3
"""Testes do playbook local — Ciclo 7 · Dia 2. Um motivo por teste."""

import copy
import importlib.util
import io
import json
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
AUTO = HERE.parent / 'automation'
_spec = importlib.util.spec_from_file_location('triage', AUTO / 'triage.py')
tr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tr)

BUNDLE = json.load(io.open(AUTO / 'fixtures-incident-001.json', encoding='utf-8'))


def run(bundle=None):
    return tr.triage(bundle if bundle is not None else BUNDLE)


class Entities(unittest.TestCase):
    def test_entities_and_custom_details_are_parsed_from_json_strings(self):
        hosts, tasks = tr.hosts_and_tasks(BUNDLE['alerts'])
        self.assertEqual(hosts, ['srvdefender01'])
        self.assertEqual(tasks, ['\\eviltask'])

    def test_input_is_never_mutated(self):
        before = json.dumps(BUNDLE, sort_keys=True)
        run()
        self.assertEqual(before, json.dumps(BUNDLE, sort_keys=True))


class Task1AuditCoverage(unittest.TestCase):
    def test_done_when_host_has_4698(self):
        self.assertEqual(run()['tasks'][0]['status'], 'DONE')

    def test_blocked_when_host_has_no_4698_silence_is_not_clean(self):
        b = copy.deepcopy(BUNDLE)
        b['tables']['SecurityEvent'] = [r for r in b['tables']['SecurityEvent'] if r['EventID'] != 4698]
        t1 = run(b)['tasks'][0]
        self.assertEqual(t1['status'], 'BLOCKED')
        self.assertIn('silencio', t1['verdict'])

    def test_blocked_when_incident_has_no_host_entity(self):
        b = copy.deepcopy(BUNDLE)
        for a in b['alerts']:
            a['Entities'] = json.dumps([e for e in json.loads(a['Entities']) if e['Type'] != 'host'])
        self.assertEqual(run(b)['tasks'][0]['status'], 'BLOCKED')


class Task2TaskContent(unittest.TestCase):
    def test_reads_principal_trigger_and_command_from_escaped_xml(self):
        t2 = run()['tasks'][1]
        self.assertEqual(t2['status'], 'DONE')
        ev = t2['evidence'][0]
        self.assertEqual(ev['UserId'], 'S-1-5-18')
        self.assertEqual(ev['Interval'], 'PT1M')
        self.assertEqual(ev['Command'], r'C:\tools\shell.cmd')

    def test_runlevel_trap_is_flagged(self):
        t2 = run()['tasks'][1]
        self.assertTrue(t2['evidence'][0]['RunLevelTrap'])
        self.assertIn('LeastPrivilege', t2['verdict'])

    def test_only_the_alerted_taskname_is_considered(self):
        names = {e['TaskName'] for e in run()['tasks'][1]['evidence']}
        self.assertEqual(names, {'\\eviltask'})


class Task3UpdatesAndEvasion(unittest.TestCase):
    def test_finds_4702_update_of_same_task(self):
        ev = run()['tasks'][2]['evidence']
        self.assertEqual(len(ev['updates_4702']), 1)
        self.assertEqual(ev['updates_4702'][0]['Command'], r'C:\Windows\Temp\b.cmd')

    def test_flags_microsoft_path_task_registered_by_human_but_not_by_machine_account(self):
        ev = run()['tasks'][2]['evidence']
        names = [e['TaskName'] for e in ev['microsoft_path_by_human']]
        self.assertEqual(names, ['\\Microsoft\\Windows\\Fake\\Updater'])


class Contract(unittest.TestCase):
    def test_playbook_never_decides(self):
        r = run()
        self.assertTrue(r['decision'].startswith('NENHUMA'))
        self.assertEqual(r['Severity'], BUNDLE['incident']['Severity'])

    def test_exit_code_is_2_when_any_task_blocked(self):
        b = copy.deepcopy(BUNDLE)
        b['tables']['SecurityEvent'] = []
        p = AUTO.parent / 'tools' / '_tmp_bundle_blocked.json'
        try:
            io.open(p, 'w', encoding='utf-8').write(json.dumps(b))
            self.assertEqual(tr.main([str(p), '--json']), 2)
        finally:
            p.unlink(missing_ok=True)


if __name__ == '__main__':
    unittest.main()
