# Ciclo 5 · Dia 1 — Modelo de dados do Sentinel e anatomia de uma regra agendada

**22/09/2026** · quatro páginas oficiais lidas hoje; nenhuma coluna escrita de memória.

---

## Rótulo de claim

```text
SYNTHETIC LAB

Workspace:    NENHUM workspace Sentinel / Log Analytics foi usado
Recurso:      NENHUM recurso Azure criado
Host:         nada instalado, nada configurado, nada executado
Schema:       páginas oficiais de referência das tabelas + doc oficial da regra agendada
Queries:      escritas e raciocinadas; NÃO executadas contra motor KQL
```

## 1. A fonte

| O quê | Onde | Data da página |
|---|---|---|
| Propriedades da regra agendada | https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview | ms.date 2024-10-16, updated 2026-07-17 |
| Tabela `SecurityEvent` | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent | 2026-08-27 |
| Tabela `DeviceProcessEvents` | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/deviceprocessevents | 2026-07-27 |
| Tabela `SigninLogs` | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs | 2026-08-27 |
| Entidades e identificadores | https://learn.microsoft.com/en-us/azure/sentinel/entities-reference | 2026-04-28 |
| Template YAML da comunidade | https://github.com/Azure/Azure-Sentinel/wiki/Contribute-to-the-Community-of-Queries | wiki |

Aviso na própria doc: a partir de **31/03/2027** o Sentinel só existe no portal do Defender.
O vocabulário de regra não muda; a casa muda.

## 2. Onde caem as três telemetrias já construídas

A pergunta do dia: **o que eu já fiz nos Ciclos 2, 3 e 4 vira que tabela no Sentinel?**

### Ciclo 3 (EVTX real, 4688/4698) → `SecurityEvent`

Descrição oficial: *"Security events collected from windows machines by Microsoft Defender
for Cloud or Microsoft Sentinel."* Solutions: `Security, SecurityInsights`.

Colunas que a regra do Ciclo 3 precisa, **confirmadas na página**:

```text
TimeGenerated        datetime
EventID              int
Computer             string
Account              string
SubjectUserName      string
SubjectDomainName    string
SubjectLogonId       string
NewProcessName       string     <- Image do Sigma
NewProcessId         string     hexadecimal
ParentProcessName    string     <- ParentImage do Sigma
CommandLine          string
Process              string
LogonType            int
IpAddress            string
EventData            string
Activity · Channel · Level · Task
```

**Achado que muda o Dia 3:** não existe coluna `TaskName` nem `TaskContent`. Os campos do
4698 (a segunda regra, do Ciclo 3.1) só existem dentro de `EventData` (string). A regra do
4698 vai exigir parse — não é uma tradução directa como a do 4688.

### Ciclo 2 (Advanced Hunting sintético) → `DeviceProcessEvents`

Descrição oficial: *"Microsoft Defender for Endpoints (MDE) device process events table."*
Solutions: `SecurityInsights`. As colunas são as mesmas do Advanced Hunting que usei no
Ciclo 2 — confirmadas: `DeviceName`, `ProcessCommandLine`, `FileName`, `FolderPath`,
`InitiatingProcessFileName`, `InitiatingProcessCommandLine`, `AccountName`, `AccountDomain`,
`ProcessId` (long), `ProcessCreationTime`, `ReportId`, `TimeGenerated`.

Logo: **as queries do CASE-01 correm tal e qual dentro do Sentinel**, se a tabela estiver
ligada. O que muda é a moldura (regra, entidade, incidente), não o KQL.

### Ciclo 4 (Graph `signIn` sintético) → `SigninLogs`

Solutions: `LogManagement`. Mapa entre o que aprendi no metadata do Graph e a coluna no
Sentinel:

| Graph `signIn` (Ciclo 4) | `SigninLogs` (hoje) | Nota oficial |
|---|---|---|
| `userPrincipalName` | `UserPrincipalName` | |
| `status.errorCode` | `ResultType` (string) | *"0 indicates success; other values are failures"* |
| `conditionalAccessStatus` | `ConditionalAccessStatus` | *"success, failure, or notApplied"* |
| `appliedConditionalAccessPolicies` | `ConditionalAccessPolicies` (dynamic) | |
| `isInteractive` | `IsInteractive` (bool) | |
| `ipAddress` | `IPAddress` | |
| `correlationId` | `CorrelationId` | |
| `riskLevelDuringSignIn` | `RiskLevelDuringSignIn` | *"hidden"* sem P2 |
| `deviceDetail` | `DeviceDetail` (dynamic) | |

A lição do Ciclo 4 Dia 2 — *`errorCode 0` ≠ entrou* — atravessa intacta: `ResultType == "0"`
é a única constante segura, e é **string**, não int.

**Não confirmado hoje:** o nome do *data connector* que alimenta cada tabela. As páginas de
referência não o dizem. Fica para o Dia 2.

## 3. Anatomia da regra agendada — só o que a doc oficial diz

Cadeia de vocabulário, nas palavras da página:

```text
eventos (resultados da query)  --[ >= alert threshold ]-->  ALERT  --[ incident settings ]-->  INCIDENT
```

| Bloco | O que a doc fixa |
|---|---|
| **Name** | única no workspace |
| **ID** | GUID atribuído só na criação; read-only |
| **Severity** | `Informational · Low · Medium · High` — definidas por **impacto**, não por certeza |
| **MITRE ATT&CK** | tácticas e técnicas da regra aplicam-se aos alertas **e** aos incidentes derivados |
| **Status** | `Enabled` por defeito; corre logo |
| **Rule query** | 1 a 10.000 caracteres; proibido `search *` e `union *`; recomenda parser ASIM em vez de tabela nativa |
| **Alert enhancement** | três tipos: entity mapping · custom details · alert details |
| **Run query every** | intervalo — 5 min a 14 dias |
| **Lookup data from the last** | lookback — 5 min a 14 dias; **intervalo ≤ lookback**, senão há buraco de cobertura |
| **Ingestion delay** | a regra corre com **5 minutos de atraso** sobre a hora marcada |
| **Alert threshold** | mínimo, máximo ou exacto; aplica-se **por execução**, não acumulado |
| **Event grouping** | `single alert` (defeito) ou `alert per event`; tecto **150** — os primeiros 149 são individuais, o 150.º resume o resto |
| **Suppression** | parar a query até 24 h depois de um alerta |
| **Results simulation** | reproduz as últimas 50 execuções sobre os dados actuais |
| **Incident settings** | criação de incidente ligada por defeito; no portal do Defender é o Defender XDR que cria |
| **Alert grouping** | até **150 alertas** por incidente; janela por defeito 5 h (5 min a 7 dias); critério: todas as entidades iguais (recomendado) · todos os alertas da regra · entidades/detalhes escolhidos |
| **Automated response** | automation rules + playbooks; gatilhos: alerta criado · incidente criado · incidente actualizado |

## 4. Entidades — o que faz um alerta ser investigável

Da referência oficial:

- até **3 identificadores por entidade** no mapeamento; a wiki da comunidade limita a **5
  tipos de entidade** por regra;
- **identificador forte** identifica sozinho; **fraco** só em combinação.

| Entidade | Fortes | Fracos | Armadilha oficial |
|---|---|---|---|
| **Account** | `Name+UPNSuffix` · `AadUserId` · `Sid` · `Name+NTDomain` (conta de domínio) · `Name+DnsDomain` · `ObjectGuid` | `Name` | se `Name` for `SYSTEM`, `ADMINISTRATOR`, `NETWORK SERVICE`, etc., **a entidade é descartada do alerta** |
| **Host** | `HostName+NTDomain` · `HostName+DnsDomain` · `AzureID` · `OMSAgentID` | `HostName` · `NetBiosName` | |
| **Process** | `Host+ProcessId+CreationTimeUtc` (+ `ImageFile`, + `FileHash`) | `ProcessId+CreationTimeUtc+CommandLine` sem Host | |

Desde **01/07/2026** `Account.Name` guarda **só o prefixo** do UPN. Quem compara `Name` com
UPN completo tem de reconstruir `Name + UPNSuffix`.

## 5. IMPLEMENTAR — a regra do Ciclo 3 traduzida para o Sentinel

Fonte: `../02-windows-evtx/sigma/marcus_schtasks_system_persistence.yml` (Dia 5 do Ciclo 3,
1 TP / 7 TN / 0 FP em dados reais).

Artefacto: `rules/marcus_schtasks_system_persistence.sentinel.yaml`, no formato de template
da comunidade (campos verbatim da wiki: `id · name · description · severity ·
requiredDataConnectors · queryFrequency · queryPeriod · triggerOperator · triggerThreshold ·
tactics · relevantTechniques · query · entityMappings · version`).

A query, sem executar:

```kusto
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith @"\schtasks.exe"
| where CommandLine contains " /create " and CommandLine contains " /ru "
| where CommandLine contains " /ru SYSTEM"
    or CommandLine contains @" /ru ""SYSTEM"""
    or CommandLine contains @" /ru NT AUTHORITY\SYSTEM"
    or CommandLine contains @" /ru ""NT AUTHORITY\SYSTEM"""
| where CommandLine contains " /sc minute"
    or CommandLine contains " /sc onstart"
    or CommandLine contains " /sc onlogon"
| where not(ParentProcessName startswith @"C:\Program Files\"
         or ParentProcessName startswith @"C:\Program Files (x86)\")
| project TimeGenerated, Computer, SubjectDomainName, SubjectUserName,
          NewProcessName, NewProcessId, ParentProcessName, CommandLine, EventID
```

Decisões de tradução, uma a uma:

| Sigma | KQL | Porquê |
|---|---|---|
| `Image\|endswith` | `NewProcessName endswith` | coluna confirmada; `endswith` é case-insensitive em KQL |
| `CommandLine\|contains` | `CommandLine contains` | **mantive `contains`, não `has`** — ver QUEBRAR |
| `ParentImage\|startswith` | `ParentProcessName startswith` | coluna confirmada |
| `level: medium` | `severity: Medium` | as definições oficiais de severidade são por impacto; persistência como SYSTEM cabe em *"limited in scope or require additional activity"* |
| `condition: all of selection_* and not filter_*` | `where` encadeados + `not(...)` | mesma álgebra |

Agendamento escolhido: `queryFrequency: 1h` · `queryPeriod: 1h` · `triggerOperator: gt` ·
`triggerThreshold: 0`. Intervalo igual ao lookback — sem sobreposição, sem buraco. Event
grouping seria **alert per event**: cada tarefa criada é um facto próprio.

## 6. QUEBRAR — onde esta tradução falha

1. **`has` vs `contains`.** O Sigma usa `contains` (substring). Em KQL, `has` procura
   **termos indexados**, não substrings — `" /ru SYSTEM"` com espaço e barra não é um termo.
   Traduzir para `has_any` mudaria o significado da regra sem ninguém dar por isso. Mantive
   `contains` e aceito o custo de desempenho que a doc de boas práticas de KQL aponta.
   **Confirmação só com fixtures — Dia 2.**
2. **`CommandLine` vazio.** Se a política de auditoria não incluir a linha de comando nos
   eventos de criação de processo, a coluna vem vazia e a regra fica **muda**. Ausência de
   telemetria ≠ ausência de actividade — lição do Ciclo 3 Dia 2, agora com consequência de
   detecção.
3. **Entidade `Account` descartada.** Se `SubjectUserName` for `SYSTEM` ou conta de
   máquina, a doc diz que a entidade sai do alerta. O alerta fica só com `Host`. O agrupamento
   por "todas as entidades iguais" passa a agrupar por máquina — mais grosso do que parece.
4. **Tecto de 150 alertas.** Em *alert per event*, uma automação que crie 300 tarefas gera
   149 alertas individuais e um resumo. O número de alertas **não** é o número de tarefas.
5. **`ParentProcessName` vazio** passa no filtro `not(startswith)`. O mesmo falso positivo
   já anotado no Sigma — o filtro só protege quando o campo existe.

## 7. TESTAR — plano, não execução

Não há motor KQL. O que existe é o método do Ciclo 3: **8 fixtures, 1 TP / 7 TN**, avaliadas
por um avaliador local (`../02-windows-evtx/tools/sigma_eval.py`). O Dia 2 decide entre:

- re-expressar as 8 fixtures como linhas `SecurityEvent` (JSON) e escrever um avaliador
  mínimo do subconjunto de KQL usado — zero instalação, reproduzível por terceiro;
- um motor Kusto externo — só se for **web, sem conta e sem instalação**; senão viola as
  regras 7 e 8 da REGRA SUPREMA.

## 8. O que a evidência sustenta

- As colunas usadas existem, com o tipo indicado, nas páginas oficiais lidas hoje.
- Os limites de agendamento, tecto de alertas, janela de agrupamento e atraso de ingestão são
  os da doc oficial, com data.
- A regra traduzida preserva a álgebra e a semântica de substring do Sigma original.

## O que a evidência NÃO sustenta

- Que a query **compila** ou devolve o que espero — não foi executada.
- Que o `connectorId` no YAML seja o nome real do conector — não confirmado hoje.
- Que a regra tenha 1 TP / 7 TN neste formato — só as fixtures do Dia 2 o dirão.
- Qualquer afirmação sobre comportamento em produção.

## 9. Limitações

- Sem workspace, sem dados reais ingeridos, sem incidente.
- `kind` e `status` não constam do template da wiki; omitidos no YAML de propósito.
- Colunas dinâmicas (`ConditionalAccessPolicies`, `DeviceDetail`, `Status`) não foram
  exploradas — entram na regra de identidade (Dia 4).

## Próximo passo

**Dia 2:** fixtures `SecurityEvent` + avaliador local; confirmar `connectorId` contra um
template real do repositório `Azure/Azure-Sentinel`; medir `contains` vs `has` nas fixtures.

---

## MARCUS REFLECTION

```text
MARCUS REFLECTION: PENDING
```

Pergunta de entrevista que este dia prepara — **não** copiar para `ENTREVISTA.md` antes de
conseguir dizer em voz alta, sem ler:

> *"Tem uma regra Sigma que funciona. O que muda quando a leva para o Sentinel?"*
