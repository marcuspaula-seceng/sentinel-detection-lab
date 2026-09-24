#!/usr/bin/env python3
"""Playbook LOCAL de triagem — Ciclo 7 (Security Automation) · Dia 1.

E o que a automation rule do Ciclo 5 Dia 6 pediu e nao tinha como correr: dado um incidente
das regras 1/2 (persistencia SYSTEM), executa as TRES tarefas de triagem sobre a telemetria
disponivel e devolve EVIDENCIA. Nao decide severidade, nao fecha, nao muda o incidente — a
decisao e do analista (e, no Sentinel, da automation rule que o chamaria).

Formatos de entrada, pelas tabelas oficiais (lidas em 22/09/2026):
  incident  -> SecurityIncident: IncidentNumber, Title, Severity, Status, RelatedAnalyticRuleIds,
               AlertIds, Labels, Tasks (dynamic -> aqui listas/dicts JSON)
  alerts    -> SecurityAlert: SystemAlertId, AlertName, Entities (STRING JSON), ExtendedProperties
               (STRING JSON; os customDetails da regra vivem aqui)
  tables    -> {"SecurityEvent": [linhas]} no mesmo formato das fixtures das regras

Tarefas (ver ../automation/triage-system-persistence-on-servers.automationrule.json):
  T1  Confirm audit coverage before trusting silence
  T2  Pull the full TaskContent XML and read Principal/Triggers/Actions
  T3  Check for 4702 updates and \\Microsoft\\ evasion

Cada tarefa devolve status DONE ou BLOCKED (falta de telemetria NAO e DONE), a evidencia
(linhas concretas) e um veredito curto. Entrada nunca e alterada. Biblioteca padrao.

    python automation/triage.py automation/fixtures-incident-001.json
    python automation/triage.py <ficheiro> --json     (so o JSON de saida)
"""

import argparse
import copy
import html
import importlib.util
import io
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
TOOLS = HERE.parent / 'tools'

_spec = importlib.util.spec_from_file_location('kql_eval', TOOLS / 'kql_eval.py')
ev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ev)

BUILTIN_ACCOUNTS = {'SYSTEM', 'LOCAL SYSTEM', 'NETWORK SERVICE', 'LOCAL SERVICE'}
# Dia 2: o primeiro teste falhou aqui — `Computer =~ "srvdefender01"` nao bate com o FQDN
# "srvdefender01.offsec.lan" (o risco escrito no QUEBRAR do DAY-01). Nome curto OU prefixo.
Q_4698_HOST = 'SecurityEvent\n| where EventID == 4698\n| where Computer =~ "{host}" or Computer startswith "{host}."'
Q_4702_HOST = 'SecurityEvent\n| where EventID == 4702\n| where Computer =~ "{host}" or Computer startswith "{host}."'
PARSE = ('| parse EventData with * \'TaskName">\' TaskName "<" *\n'
         '| parse EventData with * \'TaskContent">\' TaskContent "</Data>" *')


def _entities(alert):
    raw = alert.get('Entities') or '[]'
    return json.loads(raw) if isinstance(raw, str) else raw


def _custom_details(alert):
    raw = alert.get('ExtendedProperties') or '{}'
    props = json.loads(raw) if isinstance(raw, str) else raw
    # nos alertas reais os customDetails vao dentro de ExtendedProperties["Custom Details"]
    # como string JSON; aqui aceitam-se as duas formas
    cd = props.get('Custom Details', props.get('customDetails', {}))
    return json.loads(cd) if isinstance(cd, str) else cd


def hosts_and_tasks(alerts):
    hosts, tasknames = set(), set()
    for a in alerts:
        for e in _entities(a):
            if e.get('Type', '').lower() == 'host':
                h = e.get('HostName') or e.get('FullName')
                if h:
                    hosts.add(h.split('.')[0].lower() if e.get('HostName') else h.lower())
        cd = _custom_details(a)
        if cd.get('TaskName'):
            tasknames.add(cd['TaskName'])
    return sorted(hosts), sorted(tasknames)


def _rows_4698(tables, host):
    q = Q_4698_HOST.format(host=host) + '\n' + PARSE
    return ev.run(q, tables.get('SecurityEvent', []))[1]


def _rows_4702(tables, host):
    q = Q_4702_HOST.format(host=host) + '\n' + PARSE
    return ev.run(q, tables.get('SecurityEvent', []))[1]


def _read_task_xml(escaped):
    xml = html.unescape(escaped or '')
    find = lambda tag: (re.search(rf'<{tag}>([^<]*)</{tag}>', xml) or [None, None])[1]
    trigger = 'BootTrigger' if '<BootTrigger>' in xml else 'LogonTrigger' if '<LogonTrigger>' in xml \
        else 'TimeTrigger' if '<TimeTrigger>' in xml else 'CalendarTrigger' if '<CalendarTrigger>' in xml else None
    return {
        'UserId': find('UserId'), 'RunLevel': find('RunLevel'), 'Interval': find('Interval'),
        'Trigger': trigger, 'Command': find('Command'), 'Author': find('Author'),
    }


def task1_audit_coverage(tables, hosts):
    ev_rows = []
    for h in hosts:
        n = len(_rows_4698(tables, h))
        ev_rows.append({'host': h, 'events_4698': n})
    silent = [r['host'] for r in ev_rows if r['events_4698'] == 0]
    if not hosts:
        return {'status': 'BLOCKED', 'evidence': [], 'verdict': 'incidente sem entidade Host: nada a verificar'}
    if silent:
        return {'status': 'BLOCKED', 'evidence': ev_rows,
                'verdict': f'sem 4698 em {silent}: silencio NAO e limpo — confirmar "Audit Other Object Access Events" no host'}
    return {'status': 'DONE', 'evidence': ev_rows, 'verdict': 'ha 4698 nos hosts: a auditoria escreve; a ausencia de regra 2 teria significado'}


def task2_task_content(tables, hosts, tasknames):
    found = []
    for h in hosts:
        for r in _rows_4698(tables, h):
            if tasknames and r.get('TaskName') not in tasknames:
                continue
            info = _read_task_xml(r.get('TaskContent'))
            info.update({'host': h, 'TaskName': r.get('TaskName'), 'TimeGenerated': r.get('TimeGenerated'),
                         'RegisteredBy': r.get('SubjectUserName'),
                         'PrincipalIsSystem': info['UserId'] == 'S-1-5-18',
                         'RunLevelTrap': info['UserId'] == 'S-1-5-18' and info['RunLevel'] == 'LeastPrivilege'})
            found.append(info)
    if not found:
        return {'status': 'BLOCKED', 'evidence': [], 'verdict': 'nenhum 4698 com o TaskName do alerta: pedir o XML ao host (schtasks /query /xml)'}
    sys_ = [f for f in found if f['PrincipalIsSystem']]
    verdict = f'{len(sys_)}/{len(found)} tarefas com principal S-1-5-18'
    if any(f['RunLevelTrap'] for f in found):
        verdict += ' — RunLevel=LeastPrivilege com principal SYSTEM: o nome do campo descreve o mecanismo, nao o risco'
    return {'status': 'DONE', 'evidence': found, 'verdict': verdict}


def task3_updates_and_evasion(tables, hosts, tasknames):
    updates, evasion = [], []
    for h in hosts:
        for r in _rows_4702(tables, h):
            if not tasknames or r.get('TaskName') in tasknames:
                updates.append({'host': h, 'TaskName': r.get('TaskName'), 'TimeGenerated': r.get('TimeGenerated'),
                                'UpdatedBy': r.get('SubjectUserName'), **_read_task_xml(r.get('TaskContent'))})
        for r in _rows_4698(tables, h):
            tn = r.get('TaskName') or ''
            who = (r.get('SubjectUserName') or '').upper()
            if tn.lower().startswith('\\microsoft\\') and who not in BUILTIN_ACCOUNTS and not who.endswith('$'):
                evasion.append({'host': h, 'TaskName': tn, 'RegisteredBy': r.get('SubjectUserName'),
                                'TimeGenerated': r.get('TimeGenerated'), **_read_task_xml(r.get('TaskContent'))})
    parts = []
    if updates:
        parts.append(f'{len(updates)} actualizacao(oes) 4702 da(s) mesma(s) tarefa(s) — fora do escopo da regra 2, e aqui esta')
    if evasion:
        parts.append(f'{len(evasion)} tarefa(s) debaixo de \\Microsoft\\ registada(s) por conta humana — o filtro das regras e uma porta')
    if not parts:
        parts.append('sem 4702 nem tarefas humanas debaixo de \\Microsoft\\ nos hosts, na telemetria disponivel')
    return {'status': 'DONE', 'evidence': {'updates_4702': updates, 'microsoft_path_by_human': evasion}, 'verdict': '; '.join(parts)}


def triage(bundle):
    """bundle = {"incident": {...}, "alerts": [...], "tables": {...}}. Devolve dict novo; nao muta."""
    bundle = copy.deepcopy(bundle)
    inc, alerts, tables = bundle['incident'], bundle['alerts'], bundle.get('tables', {})
    hosts, tasknames = hosts_and_tasks(alerts)
    t1 = task1_audit_coverage(tables, hosts)
    t2 = task2_task_content(tables, hosts, tasknames)
    t3 = task3_updates_and_evasion(tables, hosts, tasknames)
    tasks = [
        {'title': 'Confirm audit coverage before trusting silence', **t1},
        {'title': 'Pull the full TaskContent XML and read Principal/Triggers/Actions', **t2},
        {'title': 'Check for 4702 updates and \\Microsoft\\ evasion', **t3},
    ]
    blocked = [t['title'] for t in tasks if t['status'] == 'BLOCKED']
    return {
        'IncidentNumber': inc.get('IncidentNumber'), 'Title': inc.get('Title'),
        'Severity': inc.get('Severity'), 'Status': inc.get('Status'),
        'RelatedAnalyticRuleIds': inc.get('RelatedAnalyticRuleIds', []),
        'hosts': hosts, 'tasknames': tasknames, 'tasks': tasks,
        'summary': ('todas as tarefas concluidas com evidencia' if not blocked
                    else f'{len(blocked)} tarefa(s) BLOQUEADA(S) por falta de telemetria: {blocked}'),
        'decision': 'NENHUMA — o playbook informa; severidade, estado e fecho sao do analista/automation rule',
    }


def render(result):
    out = [f"# Triagem — incidente {result['IncidentNumber']}: {result['Title']}",
           f"severidade={result['Severity']} estado={result['Status']} hosts={result['hosts']} tarefas={result['tasknames']}", '']
    for t in result['tasks']:
        out.append(f"## [{t['status']}] {t['title']}")
        out.append(f"veredito: {t['verdict']}")
        out.append('evidencia: ' + json.dumps(t['evidence'], ensure_ascii=False)[:600])
        out.append('')
    out += [f"**{result['summary']}**", f"decisao: {result['decision']}"]
    return '\n'.join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('bundle', help='JSON com incident, alerts e tables')
    ap.add_argument('--json', action='store_true', help='imprime so o JSON de saida')
    args = ap.parse_args(argv)
    bundle = json.load(io.open(args.bundle, encoding='utf-8'))
    result = triage(bundle)
    print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else render(result))
    return 0 if not any(t['status'] == 'BLOCKED' for t in result['tasks']) else 2


if __name__ == '__main__':
    sys.exit(main())
