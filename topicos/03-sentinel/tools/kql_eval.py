#!/usr/bin/env python3
"""Avaliador local de um SUBCONJUNTO de KQL, para correr fixtures sem motor Kusto.

Cobre apenas o que as regras desta pasta usam:

    <Tabela>
    | where <expr>
    | project <col>, <col>, ...
    | parse <col> with * '<lit>' <NovaCol> "<lit>" *      (Dia 3; modo simples do Kusto)
    | extend <NovaCol> = tostring(<col>.<campo>)          (Dia 4; um nivel de acesso dynamic)

    expr := expr 'or' expr | expr 'and' expr | 'not' '(' expr ')' | '(' expr ')'
          | <col> ('==' | '!=' | '=~') <literal>           literal: string, numero, true, false
          | <col> ('in' | '!in' | 'has_any') '(' <literal>, ... ')'
          | <col> ('endswith' | 'startswith' | 'contains' | 'has') <string>

  =~           igualdade INsensivel a maiusculas (Dia 5)
  has_any      `has` de qualquer um dos termos da lista (Dia 5)

Dia 7.1 — multi-tabela, so o que CASE-04-correlation.kql usa (run_multi):
    let Nome = 2h;                                   duracao: <n>[m|h|d]
    let Nome = <Tabela> | ... ;                      sub-query, avaliada na definicao
    | project A = B, C                               alias
    | extend Name = tostring(split(Col, "@", 0)[0])  so esta forma
    | join kind=inner <Fonte> on <Col>               inner join por UMA coluna; colisao de
                                                     nomes: a direita ganha sufixo 1 (Kusto)
    | where <T1> between (<T0> .. <T0> + <Dur>)      so esta forma; datetime ISO 8601

Semantica seguida (doc oficial de operadores de string do Kusto):
  ==          sensivel a maiusculas
  endswith / startswith / contains   INsensiveis a maiusculas, substring
  has         INsensivel a maiusculas, casa TERMOS inteiros. Um termo e uma sequencia de
              caracteres alfanumericos; o texto e partido nos nao-alfanumericos. Se o lado
              direito tiver varios termos, tem de aparecer CONSECUTIVOS no lado esquerdo.

  Literais: "..." (com \\ como escape), '...' (Dia 3, so em `parse`) e @"..." (verbatim;
  "" representa uma aspa).
  Coluna ausente ou null: toda comparacao de string devolve falso (a linha nao passa).
  parse        so a forma `* 'a' Col "b" *`: procura 'a', captura ate "b". Se 'a' ou "b" nao
               existirem, Col fica vazia (o Kusto tambem nao falha a linha; deixa vazio).

O que NAO e: um motor Kusto. Nao valida sintaxe que nao usa, nao conhece `extend`,
`summarize`, `parse_xml`, `join`, tipos dinamicos nem funcoes. Se uma regra usar algo
fora do subconjunto, o avaliador levanta erro em vez de fingir que percebeu.

Feito para correr sem instalar nada alem da biblioteca padrao.
"""

import re

_TOKEN = re.compile(
    r'''\s*(?:
        (?P<verbatim>@"(?:[^"]|"")*")   |
        (?P<string>"(?:\\.|[^"\\])*")   |
        (?P<number>\d+)                 |
        (?P<op>==|!=|=~|!in\b)          |
        (?P<lparen>\()                  |
        (?P<rparen>\))                  |
        (?P<comma>,)                    |
        (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    )''',
    re.VERBOSE,
)

_TERM = re.compile(r'[A-Za-z0-9]+')


def _tokenize(text):
    pos, out = 0, []
    while pos < len(text):
        if text[pos:].strip() == '':
            break
        m = _TOKEN.match(text, pos)
        if not m:
            raise SyntaxError(f'token desconhecido em: {text[pos:pos+30]!r}')
        pos = m.end()
        kind = m.lastgroup
        raw = m.group(kind)
        if kind == 'verbatim':
            out.append(('string', raw[2:-1].replace('""', '"')))
        elif kind == 'string':
            out.append(('string', _unescape(raw[1:-1])))
        elif kind == 'number':
            out.append(('number', int(raw)))
        elif kind == 'ident':
            low = raw.lower()
            if low in ('and', 'or', 'not', 'endswith', 'startswith', 'contains', 'has', 'in', 'has_any'):
                out.append(('kw', low))
            elif low in ('true', 'false'):
                out.append(('bool', low == 'true'))
            else:
                out.append(('ident', raw))
        else:
            out.append((kind, raw))
    return out


def _terms(text):
    return [t.lower() for t in _TERM.findall(text)]


def _has(lhs, rhs):
    needle = _terms(rhs)
    hay = _terms(lhs)
    if not needle:
        return False
    n = len(needle)
    return any(hay[i:i + n] == needle for i in range(len(hay) - n + 1))


def _compare(op, lhs, rhs):
    if lhs is None:
        # Kusto: comparar null da falso em == e em !=; a linha nao passa em nenhum dos dois.
        return False
    if op == '==':
        return lhs == rhs
    if op == '!=':
        return lhs != rhs
    if op in ('in', '!in'):
        hit = lhs in rhs
        return hit if op == 'in' else not hit
    if not isinstance(lhs, str):
        lhs = str(lhs)
    if op == 'has_any':
        return any(_has(lhs, str(v)) for v in rhs)
    if op == '=~':
        return isinstance(rhs, str) and lhs.lower() == rhs.lower()
    lo, ro = lhs.lower(), rhs.lower()
    if op == 'endswith':
        return lo.endswith(ro)
    if op == 'startswith':
        return lo.startswith(ro)
    if op == 'contains':
        return ro in lo
    if op == 'has':
        return _has(lhs, rhs)
    raise SyntaxError(f'operador nao suportado: {op}')


class _Parser:
    """Descida recursiva. Precedencia: or < and < not/atomo."""

    def __init__(self, tokens, row):
        self.t, self.i, self.row = tokens, 0, row

    def _peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def _take(self, kind=None, val=None):
        k, v = self._peek()
        if kind and k != kind or val is not None and v != val:
            raise SyntaxError(f'esperava {kind} {val!r}, obtive {k} {v!r}')
        self.i += 1
        return v

    def expr(self):
        left = self.term()
        while self._peek() == ('kw', 'or'):
            self._take()
            right = self.term()
            left = left or right
        return left

    def term(self):
        left = self.factor()
        while self._peek() == ('kw', 'and'):
            self._take()
            right = self.factor()
            left = left and right
        return left

    def factor(self):
        k, v = self._peek()
        if (k, v) == ('kw', 'not'):
            self._take()
            self._take('lparen')
            inner = self.expr()
            self._take('rparen')
            return not inner
        if k == 'lparen':
            self._take()
            inner = self.expr()
            self._take('rparen')
            return inner
        col = self._take('ident')
        k, op = self._peek()
        if (k, op) in (('op', '!in'), ('kw', 'in'), ('kw', 'has_any')):
            self._take()
            self._take('lparen')
            values = []
            while True:
                lk, lit = self._peek()
                if lk not in ('string', 'number', 'bool'):
                    raise SyntaxError(f'literal esperado em lista in, obtive {lk}')
                self._take()
                values.append(lit)
                if self._peek()[0] == 'comma':
                    self._take()
                    continue
                break
            self._take('rparen')
            list_op = '!in' if k == 'op' else op
            return _compare(list_op, self.row.get(col), values)
        if k == 'op':
            self._take()
            lk, lit = self._peek()
            if lk not in ('string', 'number', 'bool'):
                raise SyntaxError(f'literal esperado apos {op}, obtive {lk}')
            self._take()
            return _compare(op, self.row.get(col), lit)
        if k == 'kw' and op in ('endswith', 'startswith', 'contains', 'has'):
            self._take()
            lit = self._take('string')
            return _compare(op, self.row.get(col), lit)
        raise SyntaxError(f'operador esperado apos {col}, obtive {k} {op!r}')


_PARSE = re.compile(
    r'''^(?P<src>[A-Za-z_][A-Za-z0-9_]*)\s+with\s+\*\s+
        (?P<open>'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")\s+
        (?P<col>[A-Za-z_][A-Za-z0-9_]*)\s+
        (?P<close>'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")\s+\*\s*$''',
    re.VERBOSE,
)


_ESCAPES = {'\\': '\\', '"': '"', "'": "'", 'n': '\n', 't': '\t', 'r': '\r'}


def _unescape(body):
    """Escapes de string do Kusto, so os que existem: \\\\ \\" \\' \\n \\t \\r.
    Ciclo 6 Dia 1: substitui bytes(...).decode('unicode_escape'), que transformava
    'ç' em mojibake — codificava para UTF-8 e reinterpretava cada byte como Latin-1."""
    out, i = [], 0
    while i < len(body):
        ch = body[i]
        if ch == '\\' and i + 1 < len(body) and body[i + 1] in _ESCAPES:
            out.append(_ESCAPES[body[i + 1]])
            i += 2
        else:
            out.append(ch)
            i += 1
    return ''.join(out)


def _unquote(lit):
    return _unescape(lit[1:-1])


def _parse_stage(text, rows):
    m = _PARSE.match(text.strip())
    if not m:
        raise SyntaxError(f'parse fora do subconjunto (so `* lit Col lit *`): {text!r}')
    src, col = m.group('src'), m.group('col')
    lit_open, lit_close = _unquote(m.group('open')), _unquote(m.group('close'))
    out = []
    for row in rows:
        new = dict(row)
        val = row.get(src)
        new[col] = ''
        if isinstance(val, str):
            i = val.find(lit_open)
            if i != -1:
                j = val.find(lit_close, i + len(lit_open))
                if j != -1:
                    new[col] = val[i + len(lit_open):j]
        out.append(new)
    return out


_EXTEND = re.compile(
    r'^(?P<col>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*tostring\(\s*'
    r'(?P<src>[A-Za-z_][A-Za-z0-9_]*)\.(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*$'
)


def _split_top(text, sep=','):
    """Parte por `sep` so ao nivel zero de parenteses e fora de literais."""
    parts, buf, depth, quote = [], [], 0, None
    for ch in text:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
            buf.append(ch)
        elif ch == '(':
            depth += 1
            buf.append(ch)
        elif ch == ')':
            depth -= 1
            buf.append(ch)
        elif ch == sep and depth == 0:
            parts.append(''.join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    parts.append(''.join(buf).strip())
    return [p for p in parts if p]


def _extend_one(part, rows):
    m = _SPLIT_EXTEND.match(part)
    if m:
        col, src, sep, idx = m.group('col'), m.group('src'), m.group('sep'), int(m.group('idx'))
        out = []
        for row in rows:
            new = dict(row)
            val = row.get(src)
            pieces = str(val).split(sep) if isinstance(val, str) else []
            new[col] = pieces[idx] if idx < len(pieces) else ''
            out.append(new)
        return out
    m = _EXTEND.match(part)
    if not m:
        raise SyntaxError(f'extend fora do subconjunto (so `Col = tostring(Src.field)` ou '
                          f'`Col = tostring(split(Src, "sep", n)[0])`): {part!r}')
    col, src, field = m.group('col'), m.group('src'), m.group('field')
    out = []
    for row in rows:
        new = dict(row)
        val = row.get(src)
        got = val.get(field) if isinstance(val, dict) else None
        if got is None:
            new[col] = ''
        elif isinstance(got, bool):
            new[col] = 'true' if got else 'false'
        else:
            new[col] = str(got)
        out.append(new)
    return out


def _extend_stage(text, rows):
    """`extend A = ..., B = ...` — cada atribuicao e uma das duas formas suportadas.
    Kusto: tostring(null) e string vazia; campo ausente e null -> vazia."""
    for part in _split_top(text):
        rows = _extend_one(part, rows)
    return rows


_SPLIT_EXTEND = re.compile(
    r'^(?P<col>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*tostring\(\s*split\(\s*'
    r'(?P<src>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*"(?P<sep>[^"]+)"\s*,\s*(?P<idx>\d+)\s*\)\s*\[\s*0\s*\]\s*\)\s*$'
)
_BETWEEN = re.compile(
    r'^(?P<t>[A-Za-z_]\w*)\s+between\s+\(\s*(?P<t0>[A-Za-z_]\w*)\s*\.\.\s*(?P=t0)\s*\+\s*(?P<dur>[A-Za-z_]\w*)\s*\)\s*$'
)
_JOIN = re.compile(r'^kind\s*=\s*inner\s+(?P<src>[A-Za-z_]\w*)\s+on\s+(?P<col>[A-Za-z_]\w*)\s*$')
_DURATION = re.compile(r'^(?P<n>\d+)(?P<u>[mhd])$')


def _parse_time(value):
    from datetime import datetime, timezone
    if value is None:
        return None
    s = str(value).replace('Z', '+00:00')
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        # fracoes com 7 digitos (Windows) -> cortar a 6
        m = re.match(r'^(.*\.\d{6})\d+(\+00:00)$', s)
        if not m:
            raise
        dt = datetime.fromisoformat(m.group(1) + m.group(2))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _parse_duration(text):
    from datetime import timedelta
    m = _DURATION.match(text.strip())
    if not m:
        raise SyntaxError(f'duracao fora do subconjunto (<n>m|h|d): {text!r}')
    n, u = int(m.group('n')), m.group('u')
    return timedelta(**{{'m': 'minutes', 'h': 'hours', 'd': 'days'}[u]: n})


def _project_stage(text, rows):
    cols = []
    for part in text.split(','):
        part = part.strip()
        if not part:
            continue
        if '=' in part:
            alias, src = [p.strip() for p in part.split('=', 1)]
            cols.append((alias, src))
        else:
            cols.append((part, part))
    return [{alias: row.get(src) for alias, src in cols} for row in rows]


def _statements(query):
    """Separa `let ...;` da pipeline final. So ha ';' a fechar lets neste subconjunto.
    Linhas de comentario (`//`) saem ANTES de partir — um ';' num comentario nao e sintaxe."""
    code = '\n'.join(ln for ln in query.splitlines() if not ln.strip().startswith('//'))
    # partir em ';' so FORA de literais: "&lt;UserId&gt;" tem ';' e nao e fim de statement
    parts, buf, quote, i = [], [], None, 0
    while i < len(code):
        ch = code[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
            buf.append(ch)
        elif ch == ';':
            parts.append(''.join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append(''.join(buf).strip())
    lets, main = [], None
    for p in parts:
        if not p:
            continue
        if p.startswith('let '):
            name, _, body = p[4:].partition('=')
            lets.append((name.strip(), body.strip()))
        else:
            if main is not None:
                raise SyntaxError('mais de uma pipeline principal')
            main = p
    if main is None:
        raise SyntaxError('sem pipeline principal')
    return lets, main


def run_multi(query, tables):
    """Avalia uma query com `let` e `join` sobre {nome_tabela: [linhas]}. Devolve linhas."""
    lets, main = _statements(query)
    env = {}
    for name, body in lets:
        if _DURATION.match(body):
            env[name] = _parse_duration(body)
        else:
            env[name] = _pipeline(body, tables, env)
    return _pipeline(main, tables, env)


def _source_rows(name, tables, env):
    if name in env and isinstance(env[name], list):
        return [dict(r) for r in env[name]]
    if name in tables:
        return [dict(r) for r in tables[name]]
    raise SyntaxError(f'fonte desconhecida: {name}')


def _pipeline(text, tables, env):
    table, stages = _stages(text)
    out = _source_rows(table, tables, env)
    for op, body in stages:
        if op == 'where':
            m = _BETWEEN.match(body.strip())
            if m:
                dur = env.get(m.group('dur'))
                if dur is None:
                    raise SyntaxError(f'duracao nao definida em let: {m.group("dur")}')
                kept = []
                for row in out:
                    t, t0 = _parse_time(row.get(m.group('t'))), _parse_time(row.get(m.group('t0')))
                    if t is not None and t0 is not None and t0 <= t <= t0 + dur:
                        kept.append(row)
                out = kept
            else:
                out = _where_stage(body, out)
        elif op == 'project':
            out = _project_stage(body, out)
        elif op == 'extend':
            out = _extend_stage(body, out)
        elif op == 'parse':
            out = _parse_stage(body, out)
        elif op == 'join':
            m = _JOIN.match(body.strip())
            if not m:
                raise SyntaxError(f'join fora do subconjunto (so `kind=inner <Fonte> on <Col>`): {body!r}')
            right = _source_rows(m.group('src'), tables, env)
            col = m.group('col')
            joined = []
            for l in out:
                if l.get(col) is None:
                    continue
                for r in right:
                    if r.get(col) == l.get(col):
                        merged = dict(l)
                        for k, v in r.items():
                            if k == col:
                                merged[col + '1'] = v
                            elif k in merged:
                                merged[k + '1'] = v
                            else:
                                merged[k] = v
                        joined.append(merged)
            out = joined
        else:
            raise SyntaxError(f'operador de pipeline fora do subconjunto: {op}')
    return out


def _where_stage(text, rows):
    tokens = _tokenize(text)
    kept = []
    for row in rows:
        parser = _Parser(tokens, row)
        verdict = parser.expr()
        if parser.i != len(tokens):
            raise SyntaxError(f'tokens sobrantes em where: {tokens[parser.i:]}')
        if verdict:
            kept.append(row)
    return kept


def _stages(query):
    """Parte a query em (tabela, [(op, texto)...]) pelos '|' fora de literais.
    Ciclo 6 Dia 1: antes so reconhecia '|' no inicio de linha; `TA | project X` numa linha
    (valido em Kusto) dava 'fonte desconhecida'. Um teste apanhou."""
    code = ' '.join(ln.strip() for ln in query.strip().splitlines()
                    if ln.strip() and not ln.strip().startswith('//'))
    parts = _split_top(code, '|')
    if not parts:
        raise SyntaxError('query vazia')
    table = parts[0].strip()
    stages = []
    for body in parts[1:]:
        op, _, rest = body.strip().partition(' ')
        stages.append([op.lower(), rest.strip()])
    return table, stages


def run(query, rows):
    """Aplica a query as linhas. Devolve (tabela, linhas_projectadas)."""
    table, stages = _stages(query)
    out = list(rows)
    for op, text in stages:
        if op == 'where':
            out = _where_stage(text, out)
        elif op == 'project':
            out = _project_stage(text, out)
        elif op == 'parse':
            out = _parse_stage(text, out)
        elif op == 'extend':
            out = _extend_stage(text, out)
        else:
            raise SyntaxError(f'operador de pipeline fora do subconjunto: {op}')
    return table, out


def matches(query, row):
    """True se a linha sobrevive a todos os `where` da query."""
    return bool(run(query, [row])[1])
