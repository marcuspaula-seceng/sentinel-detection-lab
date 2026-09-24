# Ciclo 5 · Dia 5 — Regra de endpoint em `DeviceProcessEvents`: o CASE-01 sem mudar de coluna

**22/09/2026** · a única tabela onde as queries do ciclo anterior correm tal e qual — e a decisão sobre ASIM.

---

## Rótulo de claim

```text
SYNTHETIC LAB

Motor:        nenhum motor Kusto; avaliador local (agora com =~ e has_any)
Tenant:       NENHUM tenant MDE; NENHUM workspace
Host:         nada instalado
Dados:        13 fixtures; 6 vêm do dataset e da timeline do Ciclo 2 (DAY-01, CASE-01)
Execução:     python tools/run_tests.py  ->  45/45 nas quatro regras, exit 0
```

## 1. Por que esta tabela é diferente das outras três

No Dia 1 confirmei que `DeviceProcessEvents` no Sentinel tem **as mesmas colunas** do
Advanced Hunting que o Ciclo 2 usou. Hoje a prova: os operadores do CASE-01 (`=~`,
`has_any`, `has`) e as colunas (`FileName`, `ProcessCommandLine`,
`InitiatingProcessFileName`) entram na regra **sem tradução**. Não há `parse`, não há
escape, não há tipo a corrigir.

O que muda é só a moldura — conector, entidade, agendamento.

## 2. Template real — o que copiei

`Solutions/Microsoft Defender XDR/Analytic Rules/PotentialBuildProcessCompromiseMDE.yaml`
v1.1.0, via `gh api`: `connectorId: MicrosoftThreatProtection` · `dataTypes:
DeviceProcessEvents` · `status: Available` · `kind: Scheduled`.

## 3. ASIM — a decisão, com razão escrita

A doc da regra agendada (Dia 1) recomenda parser ASIM em vez de tabela nativa. O schema
`ProcessEvent` v1.0.0 (lido hoje) dá `imProcessCreate` com `TargetProcessName`,
`TargetProcessCommandLine`, `ActingProcessName`, `ActorUsername`, `DvcHostname` e aliases
`Process`, `CommandLine`, `User`.

**Não usei ASIM.** Duas razões, ambas de evidência e não de preguiça:

1. O avaliador local não modela um parser — testar `imProcessCreate` seria testar o meu
   mapeamento imaginado de `ProcessCommandLine → TargetProcessCommandLine`, não o parser.
2. As regras ASIM reais listam **quatro conectores** (`BackupDeletion.yaml`:
   `MicrosoftDefenderAdvancedThreatProtection`, `MicrosoftThreatProtection`,
   `WindowsSecurityEvents`, `WindowsForwardedEvents`). Afirmar isso sem poder verificar o
   parser seria copiar forma sem conteúdo.

Fica como **limitação declarada** e como candidato natural ao CASE-04: a mesma regra em
ASIM cobriria 4688 (`SecurityEvent`) e MDE numa só query — o que a regra 1 e esta regra 4
fazem hoje em separado.

## 4. IMPLEMENTAR — regra 4

`rules/marcus_powershell_script_from_temp_path.sentinel.yaml`, do CASE-01 achados 4, 5 e 7:

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has "-File"
| where ProcessCommandLine has_any (@"\AppData\Local\Temp\", @"\Windows\Temp\", @"\Downloads\")
| where not(InitiatingProcessFolderPath startswith @"C:\Program Files\"
         or InitiatingProcessFolderPath startswith @"C:\Program Files (x86)\")
| project TimeGenerated, DeviceName, AccountDomain, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessId,
          ProcessCreationTime, SHA256
```

**Escopo estreito de propósito:** só `-File`. `-Command "& <path>"`, `-EncodedCommand` e
`IEX` são outras regras — o `-enc` é o Dia 1 do Ciclo 2. Uma regra, um comportamento
(mesma decisão do Dia 4).

Entidades: `Host.FullName ← DeviceName` (a doc diz que `DeviceName` é FQDN; `HostName +
DnsDomain` exigiria `split()`), `Account.Name/NTDomain`, `Process.ProcessId/CommandLine/
CreationTimeUtc` — a primeira regra do ciclo com os três identificadores de processo que a
doc de entidades chama fortes **quando ligados a Host**.

## 5. O avaliador cresceu — `=~` e `has_any`

Os dois operadores que o CASE-01 já usava. `=~` é igualdade insensível a maiúsculas;
`has_any` é `has` sobre uma lista. Nada mais.

## 6. TESTAR / QUEBRAR — as 13 fixtures

```text
=> 5 TP / 8 TN / 0 FAIL      variante `has`: 0 divergências (a regra já usa has)
```

| # | Fixture | Veredito | O que prova |
|---|---|---|---|
| 1–3 | DAY-01 #1 chrome · #2 `Get-Service` · #3 `-enc` | NO | não é PowerShell / sem `-File` / **é outra regra** |
| 4 | CASE-01 passo 1 — `Invoke-WebRequest` | NO | o download é o achado 1, não esta regra |
| 5 | **CASE-01 passo 4 — `-File …\Temp\a.ps1`** | **MATCH** | a linha para a qual a regra existe |
| 6 | CASE-01 passo 5 — `cmd.exe /c net user` | NO | achado 6, regra pai→filho |
| 7 | **CASE-01 achado 7 — `Run "Updater"` a executar** | **MATCH** | a regra vê a persistência a **correr**, não a ser escrita (isso é `DeviceRegistryEvents`) |
| 8 | `-File C:\Scripts\deploy.ps1` | NO | pasta de administração |
| 9 | `pwsh.exe -File …\Downloads\` | MATCH | segundo binário, terceira pasta |
| 10 | tudo em MAIÚSCULAS | MATCH | `=~`, `has`, `has_any` insensíveis |
| 11 | **`-Command "& …\Temp\a.ps1"`** | NO | evasão trivial — **falso negativo assumido** pelo escopo |
| 12 | instalador em Program Files corre de `\Windows\Temp\` | NO | ramo do filtro |
| 13 | `InitiatingProcessFolderPath` null | MATCH | o filtro só protege quando o campo existe (= regra 1, fixture 6) |

## 7. O que a evidência sustenta

- Colunas e operadores do Ciclo 2 valem sem alteração em `DeviceProcessEvents`.
- Conector e moldura batem com um template publicado pela Microsoft.
- A fronteira da regra (`-Command`, filtro contornável) está em código, não em prosa.

## O que a evidência NÃO sustenta

- Que ASIM mapeia estas colunas como imagino — **não verificado**, por isso não usado.
- Que a query compila num Kusto real.
- Que `DeviceName` vem sempre como FQDN em dados reais (a doc diz que sim; não vi dados).

## 8. Limitações

- `-File` só; `\Users\Public\` não está na lista de pastas (o CASE-03 do Ciclo 3 tinha
  `C:\Users\Public\svc.exe` — fica como pergunta em aberto, não como omissão silenciosa).
- Sem `DeviceFileEvents`/`DeviceRegistryEvents`: a cadeia completa do CASE-01 é o CASE-04.

## Próximo passo

**Dia 6:** modelo de incidente — como as quatro regras viram alertas, como os alertas se
agrupam em incidentes (entidades fortes/fracas, janela de 5 h, tecto de 150), e uma
automation rule modelada. Nada a executar; tudo a raciocinar com os limites do Dia 1.

---

## MARCUS REFLECTION

```text
MARCUS REFLECTION: PENDING
```

Pergunta de entrevista deste dia — só para `ENTREVISTA.md` quando sair em voz alta, sem ler:

> *"A doc manda usar ASIM. Você não usou. Por quê, e o que perdeu?"*
