#!/usr/bin/env python3
"""Linter local dos templates de regra — Ciclo 6 (Python Security) · Dia 2.

Aproxima o que DetectionTemplateStructureValidationTests faria no repositorio da
comunidade, com o que a doc oficial fixa (Ciclo 5 · Dia 1) e o que os templates reais
mostram (Dias 2-6). Nao substitui a validacao real; apanha o que se apanha sem workspace.

Cada verificacao diz de onde vem a regra. Sai com codigo 1 se alguma regra falhar.

    python tools/lint_rules.py
"""

import io
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = ROOT / 'rules'

GUID = re.compile(r'^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$')
DURATION = re.compile(r'^(\d+)([mhd])$')                    # forma usada nos templates reais (1h, 1d, 2h)
ISO_DURATION = re.compile(r'^P(T\d+[HM]|\d+D)$')           # lookbackDuration: PT5H nos templates reais
TECHNIQUE = re.compile(r'^T\d{4}(\.\d{3})?$')
SEMVER = re.compile(r'^\d+\.\d+\.\d+$')

SEVERITIES = {'Informational', 'Low', 'Medium', 'High'}    # doc da regra agendada
TRIGGER_OPS = {'gt', 'lt', 'eq', 'ne'}                     # 'gt' visto em templates; os outros por conhecimento, nao confirmados hoje
TACTICS = {                                                # nomes MITRE como aparecem nos templates (sem espacos)
    'Reconnaissance', 'ResourceDevelopment', 'InitialAccess', 'Execution', 'Persistence',
    'PrivilegeEscalation', 'DefenseEvasion', 'CredentialAccess', 'Discovery', 'LateralMovement',
    'Collection', 'CommandAndControl', 'Exfiltration', 'Impact', 'ImpairProcessControl',
    'InhibitResponseFunction', 'PreAttack',
}
MATCHING = {'AllEntities', 'AnyAlert', 'Selected'}
AGGREGATION = {'SingleAlert', 'AlertPerResult'}
REQUIRED = ['id', 'name', 'description', 'severity', 'requiredDataConnectors', 'queryFrequency',
            'queryPeriod', 'triggerOperator', 'triggerThreshold', 'tactics', 'relevantTechniques',
            'query', 'entityMappings', 'version', 'kind']


def minutes(d):
    n, u = DURATION.match(d).groups()
    return int(n) * {'m': 1, 'h': 60, 'd': 1440}[u]


def lint(rule, name):
    errs = []
    E = errs.append
    for k in REQUIRED:
        if k not in rule:
            E(f'campo obrigatorio ausente: {k}  [wiki + templates reais]')
    if errs:
        return errs
    if not GUID.match(str(rule['id'])):
        E('id nao e GUID minusculo  [wiki: id]')
    if rule['severity'] not in SEVERITIES:
        E(f'severity {rule["severity"]!r} fora de {sorted(SEVERITIES)}  [doc: Severity]')
    for k in ('queryFrequency', 'queryPeriod'):
        if not DURATION.match(str(rule[k])):
            E(f'{k} nao esta na forma <n>[mhd]  [templates reais: 1h, 1d, 2h]')
    if all(DURATION.match(str(rule[k])) for k in ('queryFrequency', 'queryPeriod')):
        f, p = minutes(rule['queryFrequency']), minutes(rule['queryPeriod'])
        if f > p:
            E(f'queryFrequency ({f} min) > queryPeriod ({p} min): buraco de cobertura  [doc: interval <= lookback]')
        for k, v in (('queryFrequency', f), ('queryPeriod', p)):
            if not 5 <= v <= 14 * 1440:
                E(f'{k} fora de 5 min .. 14 dias  [doc: Query scheduling]')
    if rule['triggerOperator'] not in TRIGGER_OPS:
        E(f'triggerOperator {rule["triggerOperator"]!r} fora de {sorted(TRIGGER_OPS)}')
    if not isinstance(rule['triggerThreshold'], int) or rule['triggerThreshold'] < 0:
        E('triggerThreshold deve ser inteiro >= 0')
    for t in rule['tactics']:
        if t not in TACTICS:
            E(f'tactic {t!r} desconhecida  [nomes MITRE sem espacos, como nos templates]')
    for t in rule['relevantTechniques']:
        if not TECHNIQUE.match(str(t)):
            E(f'technique {t!r} nao e Txxxx[.xxx]')
    q = rule['query']
    if not 1 <= len(q) <= 10000:
        E(f'query com {len(q)} caracteres; limite 1..10000  [doc: Rule query]')
    if re.search(r'\bsearch\s+\*', q) or re.search(r'\bunion\s+\*', q):
        E('query usa search * ou union *  [doc: proibido]')
    if not rule['requiredDataConnectors']:
        E('requiredDataConnectors vazio')
    for c in rule['requiredDataConnectors']:
        if 'connectorId' not in c or not c.get('dataTypes'):
            E(f'connector incompleto: {c}')
    ems = rule['entityMappings']
    if not ems:
        E('entityMappings vazio  [wiki: obrigatorio em detections]')
    if len(ems) > 5:
        E(f'{len(ems)} entityTypes; maximo 5  [wiki]')
    for em in ems:
        fm = em.get('fieldMappings') or []
        if not 1 <= len(fm) <= 3:
            E(f'entity {em.get("entityType")}: {len(fm)} identificadores; permitido 1..3  [doc: entities]')
        for m in fm:
            if 'identifier' not in m or 'columnName' not in m:
                E(f'fieldMapping incompleto em {em.get("entityType")}: {m}')
            elif m['columnName'] not in q:
                E(f'entity {em.get("entityType")}: columnName {m["columnName"]!r} nao aparece na query')
    if not SEMVER.match(str(rule['version'])):
        E('version nao e x.y.z')
    if rule['kind'] != 'Scheduled':
        E(f'kind {rule["kind"]!r}; esperado Scheduled  [templates reais]')
    ic = rule.get('incidentConfiguration')
    if ic:
        gc = ic.get('groupingConfiguration', {})
        if gc.get('matchingMethod') not in MATCHING:
            E(f'matchingMethod {gc.get("matchingMethod")!r} fora de {sorted(MATCHING)}')
        if gc.get('matchingMethod') == 'Selected' and not gc.get('groupByEntities'):
            E('matchingMethod Selected sem groupByEntities  [doc: exige pelo menos uma entidade]')
        if not ISO_DURATION.match(str(gc.get('lookbackDuration', ''))):
            E(f'lookbackDuration {gc.get("lookbackDuration")!r} nao e ISO 8601 (PT5H, P1D)')
    eg = rule.get('eventGroupingSettings')
    if eg and eg.get('aggregationKind') not in AGGREGATION:
        E(f'aggregationKind {eg.get("aggregationKind")!r} fora de {sorted(AGGREGATION)}')
    for k, col in (rule.get('customDetails') or {}).items():
        if col not in q:
            E(f'customDetails {k}: coluna {col!r} nao aparece na query')
    return errs


def main():
    rules = sorted(RULES.glob('*.sentinel.yaml'))
    if not rules:
        print('nenhuma regra em', RULES)
        return 1
    bad = 0
    for path in rules:
        try:
            rule = yaml.safe_load(io.open(path, encoding='utf-8'))
        except yaml.YAMLError as exc:
            print(f'FAIL  {path.name}: YAML invalido: {exc}')
            bad += 1
            continue
        errs = lint(rule, path.name)
        print(f"{'FAIL' if errs else 'PASS'}  {path.name}")
        for e in errs:
            print(f'        - {e}')
        bad += bool(errs)
    print(f'\n{len(rules) - bad}/{len(rules)} regras PASS no linter')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
