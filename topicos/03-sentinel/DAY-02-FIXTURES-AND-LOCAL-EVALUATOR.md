# Ciclo 5 · Dia 2 — Fixtures `SecurityEvent`, avaliador local e `contains` vs `has`

**22/09/2026** · a regra do Dia 1 deixou de ser só raciocinada: correu contra 10 linhas.

---

## Rótulo de claim

```text
SYNTHETIC LAB

Motor:        NENHUM motor Kusto. Avaliador próprio de um SUBCONJUNTO de KQL (tools/kql_eval.py)
Workspace:    nenhum
Host:         nada instalado — Python 3.11 e PyYAML já existiam (Ciclo 3)
Dados:        10 fixtures sintéticas; 8 são as do Ciclo 3 re-expressas como SecurityEvent
Execução:     python tools/run_tests.py  ->  exit 0
```

## 1. Objectivo

Três perguntas deixadas em aberto pelo Dia 1:

1. A regra traduzida preserva o veredito das 8 fixtures do Ciclo 3 (1 TP / 7 TN lá — aqui
   os positivos são 3 porque o Ciclo 3 contava só o sample real como TP)?
2. `contains` e `has` são mesmo diferentes, ou é preciosismo?
3. Qual é o `connectorId` real?

## 2. Dataset — de onde vem cada linha

`tools/fixtures-securityevent.json`. Mapa de colunas Sigma → `SecurityEvent` aplicado às
8 fixtures do Ciclo 3 (`../02-windows-evtx/tools/fixtures-synthetic.json`), sem alterar um
byte da `CommandLine`:

| Ciclo 3 | `SecurityEvent` |
|---|---|
| `Image` | `NewProcessName` |
| `ParentImage` | `ParentProcessName` |
| `User` (`DOM\user`) | `SubjectDomainName` + `SubjectUserName` |
| — | `TimeGenerated`, `NewProcessId` (hex, como a doc descreve) |

Mais **duas fixtures novas**, desenhadas para separar `contains` de `has`:

- **Divergência A** — `/ru  SYSTEM` com dois espaços. Substring exacta falha; termos casam.
- **Divergência B** — conta de utilizador, mas `/tr C:\ru\SYSTEM\sync.cmd`. Substring
  `" /ru SYSTEM"` não existe; os termos `[ru, system]` aparecem consecutivos.

Cada fixture declara **dois** vereditos esperados: `_expected` (regra oficial) e
`_expected_has_variant`. O runner só conta PASS/FAIL contra o primeiro.

## 3. O avaliador — o que é e o que não é

`tools/kql_eval.py`, biblioteca padrão apenas. Cobre `where`, `project`, `==`, `endswith`,
`startswith`, `contains`, `has`, `and`/`or`/`not()`, parêntesis, literais `"..."` e
`@"..."`. Semântica copiada da doc de operadores de string do Kusto:

- `==` sensível a maiúsculas; os quatro operadores de string **in**sensíveis;
- `has` parte o texto em termos alfanuméricos e exige os termos do lado direito
  **consecutivos** no lado esquerdo;
- coluna ausente ou `null` → comparação falsa (a linha não passa).

**Fora do subconjunto, levanta erro** em vez de fingir — `extend`, `parse_xml`, `summarize`,
`join`, tipos `dynamic`. Isto é deliberado: o Dia 3 (4698 via `EventData`) vai bater aqui,
e é bom que bata com ruído.

## 4. Resultado — regra oficial

```text
python tools/run_tests.py
=> 4 TP / 6 TN / 0 FAIL em 10 fixtures      exit 0
```

As 8 do Ciclo 3 dão o **mesmo veredito** que davam no Sigma. A tradução não mudou a regra.

## 5. Resultado — `contains` vs `has`

A variante é a mesma query com `contains` → `has` (regex `\bcontains\b`), sem mais nada.

```text
=> a variante `has` diverge da oficial em 2 de 10 fixtures
   Divergência A   has=MATCH     oficial=NO MATCH
   Divergência B   has=MATCH     oficial=NO MATCH
```

Leitura:

| | `contains` (oficial) | `has` |
|---|---|---|
| Espaço duplo antes de `SYSTEM` | **falso negativo** — evasão trivial | apanha |
| `\ru\SYSTEM\` num caminho de `/tr` | correcto | **falso positivo** |
| Nas 8 fixtures "normais" | 8/8 | 8/8 |

Nem um é "o certo". `contains` é fiel ao Sigma e cego a *padding*; `has` é robusto a
pontuação e cego ao contexto. **Nas 8 fixtures originais são indistinguíveis — só as duas
fixtures desenhadas para o efeito mostram a diferença.** Uma suíte que passa não prova que
dois operadores são equivalentes; prova que a suíte não os separa.

Decisão: a regra fica em `contains` (fidelidade ao Sigma validado em dados reais). A
evasão por espaço duplo entra em *limitações* — o remédio limpo seria `matches regex`
com `\s+`, que fica para depois do CASE-04, não agora.

## 6. `connectorId` — confirmado em templates reais

Lidos via `gh api` do repositório `Azure/Azure-Sentinel`, pasta
`Solutions/Windows Security Events/Analytic Rules/`:

| Template | `connectorId` | `status` | `kind` | frequência |
|---|---|---|---|---|
| `ScheduleTaskHide.yaml` v1.0.1 | `SecurityEvents` **e** `WindowsSecurityEvents` | `Available` | `Scheduled` | `1d`/`1d` |
| `PotentialFodhelperUACBypass.yaml` v1.0.2 | os mesmos dois | `Available` | `Scheduled` | `2h`/`2h` |

Dois conectores porque são dois agentes (legado e AMA) a alimentar a mesma tabela. A wiki
não mostrava `status` nem `kind`; os templates reais têm ambos. YAML actualizado.

Bónus do `ScheduleTaskHide`: mostra **exactamente** o padrão de parse que o Dia 3 precisa —
`parse_xml(EventData).EventData.Data` → `mv-expand` → `bag_unpack` → `pivot` →
`column_ifexists`. Não é invenção minha; é o que a Microsoft faz para ler campos que só
existem em `EventData`.

## 7. O que a evidência sustenta

- 10/10 fixtures no veredito declarado, com o avaliador local.
- `contains` e `has` divergem em 2 casos construídos e coincidem nos 8 herdados.
- Os campos do YAML batem com dois templates publicados pela Microsoft.

## O que a evidência NÃO sustenta

- Que a query **compila num motor Kusto real** — o avaliador é meu, não é o Kusto.
- Que a semântica de `has` implementada é bit-a-bit a do Kusto (termos de 1–2 caracteres e
  o índice de termos têm regras que não modelei).
- Que a regra passa em `DetectionTemplateStructureValidationTests`.
- Qualquer coisa sobre produção.

## 8. Limitações

- Avaliador cobre 7 operadores; o Dia 3 vai precisar de mais e vai falhar por desenho.
- `NewProcessId` e `TimeGenerated` são inventados por fixture — servem à entidade, não à lógica.
- Encoding: o console Windows em cp1252 mostra o travessão como `�`; o ficheiro é UTF-8.

## Próximo passo

**Dia 3:** segunda regra — Event **4698** via parse de `EventData`, seguindo o padrão do
`ScheduleTaskHide`. Decidir se o avaliador cresce (`extend` + `parse_xml` mínimo) ou se as
fixtures já trazem os campos extraídos e o parse fica declarado como não testado.

---

## MARCUS REFLECTION

```text
MARCUS REFLECTION: PENDING
```

Pergunta de entrevista deste dia — só para `ENTREVISTA.md` quando sair em voz alta, sem ler:

> *"A sua suíte de testes passa a 100%. Como sabe que ela testa alguma coisa?"*
