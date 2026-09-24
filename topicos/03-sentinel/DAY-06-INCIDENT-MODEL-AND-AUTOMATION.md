# Ciclo 5 · Dia 6 — Modelo de incidente e automação: o que acontece depois da query

**22/09/2026** · nada a executar; tudo a raciocinar com os limites da doc e os enums do schema.

---

## Rótulo de claim

```text
MODEL ONLY

Workspace:    nenhum. Nenhuma regra criada, nenhum incidente visto, nenhuma automação corrida.
Fontes:       doc da regra agendada (Dia 1) · entidades (Dia 1) · doc de automation rules ·
              schema ARM Microsoft.SecurityInsights/automationRules@2025-10-01-preview ·
              template real CTERA/MassDeletions.yaml (forma de incidentConfiguration)
Execução:     python tools/run_tests.py continua 45/45 — os campos novos não tocam a query
```

## 1. A cadeia, nas palavras da doc

```text
linhas da query  --[ threshold: gt 0 ]-->  ALERTAS  --[ event grouping ]-->  N alertas
                                                     --[ incident settings + alert grouping ]-->  INCIDENTES
                                                     --[ automation rules, por ordem ]-->  triagem
```

Três decisões por regra, e nenhuma delas está na query:

| Decisão | Campo do template | Opções (doc) |
|---|---|---|
| Quantos alertas por execução | `eventGroupingSettings.aggregationKind` | `SingleAlert` (defeito) · `AlertPerResult` (tecto 150; o 150.º resume) |
| Se nasce incidente | `incidentConfiguration.createIncident` | `true` (defeito); no portal do Defender quem cria é o XDR |
| Como os alertas se juntam | `groupingConfiguration.matchingMethod` | `AllEntities` (recomendado) · `AnyAlert` · `Selected` (+ `groupByEntities`) · janela 5 min–7 d, defeito PT5H · até 150 alertas por incidente |

## 2. As quatro regras, uma a uma

| Regra | Entidades mapeadas | Força (doc) | `aggregationKind` | Agrupamento | Porquê |
|---|---|---|---|---|---|
| 1 · 4688 schtasks | Host (`HostName`), Account (`Name+NTDomain`), Process (`ProcessId+CreationTimeUtc+CommandLine`) | Host **fraco** sozinho; Account **forte** se domínio; Process **forte** só ligado a Host — e o mapeamento não liga | `AlertPerResult` | `AllEntities` PT5H | cada tarefa criada é um facto; três entidades iguais = mesma acção repetida |
| 2 · 4698 | Host, Account (**quem registou**) | idem | `AlertPerResult` | `AllEntities` PT5H | se Host+Account baterem com a regra 1, **os dois alertas caem no mesmo incidente** — 4688 e 4698 do mesmo acto, juntos |
| 3 · SigninLogs | Account (`FullName`), IP (`Address`) | `FullName` é compat; IP **forte** só se global | `AlertPerResult` | **`Selected` → `Account`** | a mesma sessão dá uma linha por app (fixtures 3 e 4); `AllEntities` daria um incidente **por IP** se a pessoa mudasse de rede; por conta é o que um analista quer |
| 4 · DeviceProcessEvents | Host (`FullName`), Account, Process | Process único por execução | `AlertPerResult` | `AllEntities` PT5H | **decisão consciente:** a persistência a correr de novo (fixture 7) abre incidente novo — cada execução é evidência própria |

Dois pontos que o modelo revela e a query escondia:

1. **A regra 1 e a regra 2 correlacionam-se sozinhas** — sem `join`, sem CASE. Basta que
   `Computer`/`SubjectUserName` batam nas duas e a janela de 5 h os apanhe. É a correlação
   mais barata do Sentinel: **partilhar entidades**.
2. **`Account.Name` = `SYSTEM` é descartado** (Dia 1). Na regra 2 mapeei quem *registou*
   (`admmig`), não o principal — de propósito. Se tivesse mapeado o principal, o alerta
   ficaria só com Host e o agrupamento passaria a ser "por máquina".

`customDetails` acrescentado às quatro: os campos que um analista abre primeiro
(`TaskCommandLine`, `TaskName`, `Country`/`CAStatus`, `ScriptCommandLine`/`ScriptHash`) —
para não ter de abrir a query.

## 3. A regra de automação — modelada com o schema, não de memória

`automation/triage-system-persistence-on-servers.automationrule.json`.

| Bloco | Valor | Fonte |
|---|---|---|
| `triggersOn` / `triggersWhen` | `Incidents` / `Created` | enum do schema; a doc diz que automação por incidente é o caso normal |
| Condições (AND implícito) | `IncidentRelatedAnalyticRuleIds Contains [regra 1, regra 2]` · `HostName StartsWith srv` · `IncidentSeverity NotEquals High` | `propertyName` e `operator` do enum; `HostName` está na referência de propriedades de entidade |
| Acção 1 | `ModifyProperties`: `severity High`, `status Active`, 3 labels | enum `severity`/`status` |
| Acções 2–4 | `AddIncidentTask` × 3 | as três perguntas que o Ciclo 3 provou decidirem o caso: **auditoria ligada?** · **TaskContent inteiro** · **4702 e `\Microsoft\`** |
| `order` | 1 | regras correm em sequência; a seguinte vê o estado já alterado |

O que ficou **de fora, com razão**: `RunPlaybook` (exige `logicAppResourceId` de um recurso
que não existe); `expirationTimeUtc` (é para supressão temporária — pen-test, manutenção —
não para triagem permanente); `PropertyChanged` (é do gatilho `Updated`).

## 4. QUEBRAR — onde o modelo falha

1. **`HostName StartsWith srv`** é convenção de nomes, não inventário. Um servidor chamado
   `dc01` não é triado. Em produção a condição certa é uma **watchlist** de servidores —
   mesma lição da lista de países do Dia 4.
2. **`IncidentRelatedAnalyticRuleIds`** exige os IDs de recurso das regras **criadas**; os
   GUIDs do YAML são os do template. O JSON está certo em forma e errado em valor até haver
   workspace — está dito no `_comment`.
3. **Portal do Defender (obrigatório a partir de 31/03/2027):** quem cria incidentes é o
   XDR; `reopenClosedIncident` deixa de existir; nomes de alerta personalizados podem ser
   sobrepostos. O modelo foi feito para o Sentinel "clássico" e envelhece em 6 meses.
4. **Tecto de 150:** `AlertPerResult` numa automação que crie 300 tarefas dá 149 alertas +
   1 resumo, e o agrupamento junta 150 por incidente e abre outro. O número de incidentes
   **não** é o número de tarefas — o Dia 1 já o dizia; aqui é consequência.

## 5. O que a evidência sustenta

- Os campos adicionados aos YAML existem, com esses nomes e essa ordem, num template real.
- Os enums do JSON são os do schema ARM publicado, com data.
- As decisões de agrupamento derivam das fixtures dos Dias 2–5, não de preferência.

## O que a evidência NÃO sustenta

- Que `matchingMethod: Selected` + `groupByEntities` estão certos **no formato YAML da
  comunidade** — vi só `AllEntities` num template real; o nome dos campos vem do schema ARM
  de `scheduledAlertRules`. Declarado no YAML da regra 3.
- Que a automação **corre** — nunca foi criada.
- Que `HostName` chega à condição com o valor que espero (depende do mapeamento `FullName`
  vs `HostName` na regra 4 — a regra 4 mapeia `FullName`, que a doc chama compat; a
  condição de automação lê `Host: HostName`. **Risco real:** a regra 4 pode não ser triada
  por esta automação. As regras 1 e 2 mapeiam `HostName` e são as que a automação visa.)

## 6. Limitações

- Sem playbook, sem gatilho `Updated`, sem supressão.
- Modelo feito para o Azure portal; a migração para o Defender portal muda a criação de
  incidentes.

## Próximo passo

**Dia 7 — CASE-04:** correlação endpoint + Windows + identidade num incidente só. Com o
modelo de hoje, a pergunta muda: **que entidades as quatro regras teriam de partilhar para
o Sentinel os juntar sozinho — e onde isso não chega e é preciso `join`?**

---

## MARCUS REFLECTION

```text
MARCUS REFLECTION: PENDING
```

Pergunta de entrevista deste dia — só para `ENTREVISTA.md` quando sair em voz alta, sem ler:

> *"Duas regras diferentes disparam para o mesmo ataque. Como é que o Sentinel sabe que é o mesmo incidente — e quando é que não sabe?"*
