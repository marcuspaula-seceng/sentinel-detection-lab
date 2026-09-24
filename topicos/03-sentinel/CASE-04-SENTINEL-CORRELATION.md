# CASE-04 — Correlação no Sentinel: endpoint + Windows + identidade

**Ciclo 5 · artefacto principal · 22/09/2026**

---

## Environment and claim label

```text
SYNTHETIC LAB — MODEL

Workspace:    NENHUM. Nenhuma regra criada, nenhum incidente visto.
Dados:        as 45 fixtures dos Dias 2–5 (3 famílias: SecurityEvent, SigninLogs,
              DeviceProcessEvents), mais nada.
Queries:      as 4 regras testadas localmente (45/45); a query de correlação (join)
              NÃO foi executada nem testada — o avaliador não tem join, e isso está
              declarado em vez de simulado.
Host:         nada instalado.
```

**Formulação permitida:** *Incident correlation modelling lab across three synthetic
telemetry families using Microsoft Sentinel entity and grouping semantics.*
**Nunca:** *real correlated incident · production SOC · Sentinel tenant lab.*

## 1. A pergunta

Os Ciclos 2, 3 e 4 produziram três casos separados: um endpoint (CASE-01), um Windows
(CASE-02) e uma identidade (CASE-03). O Ciclo 5 traduziu-os em quatro regras. A pergunta
deste caso não é "o que aconteceu" — é:

> **Se estas quatro regras dispararem, o Sentinel junta-as num incidente sozinho? Onde
> sim, porquê; onde não, o que falta?**

## 2. O que as fixtures dizem — medido, não imaginado

Entidades que cada regra **emite** nas suas fixtures positivas:

| Regra | Positivos | Host | Account | Process / IP |
|---|---|---|---|---|
| 1 · 4688 schtasks | 4 | `srvdefender01.offsec.lan`, `srv02.lab.local`, `srv03.lab.local` | `admmig`+`OFFSEC`, `u1`+`LAB`, `svc-backup`+`LAB` | `NewProcessId` + hora + `CommandLine` |
| 2 · 4698 | 4 | `srvdefender01.offsec.lan` | `admmig`+`OFFSEC` | — |
| 3 · SigninLogs | 3 | — | `j.silva@example.com` (**FullName**), `m.rocha@example.com` | IP `198.51.100.7`, `198.51.100.33` |
| 4 · DeviceProcessEvents | 5 | `pc-003.example.com`, `pc-004.example.com` | `u3`+`EXAMPLE`, `u4`+`EXAMPLE` | `ProcessId` + hora |

Aplicando o agrupamento do Dia 6 (`AllEntities`, janela 5 h):

```text
Regra 1 (srvdefender01 / admmig)  +  Regra 2 (srvdefender01 / admmig)   ->  MESMO incidente
                                                                             (Host e Account iguais; o Process da regra 1
                                                                              não existe na 2 — "todas as entidades" compara
                                                                              as que existem em ambos os alertas)
Regra 3 (j.silva@example.com / IP)                                       ->  incidente PRÓPRIO
Regra 4 (pc-003 / u3 / Process)                                          ->  incidente PRÓPRIO, um por execução
```

**Resultado honesto: com as fixtures de hoje, as três famílias não se correlacionam.**
Não porque o Sentinel falhe — porque os três casos originais foram escritos em três
universos (`offsec.lan`, `lab.local`, `example.com`) com contas diferentes. O Sentinel
correlaciona **entidades iguais**, e não há nenhuma.

Isto é o achado central do ciclo: **correlação não é uma feature que se liga; é uma
propriedade dos dados.** Se o mesmo humano aparece como `j.silva@example.com` na
identidade, `u3` no endpoint e `admmig` no servidor, nenhuma janela de 5 h o junta.

> ⚠ Sobre a regra 1 + regra 2: o comportamento de `AllEntities` quando um alerta tem uma
> entidade que o outro não tem (Process) é o que a doc descreve — *"alerts are grouped
> together if they share identical values for each of the mapped entities"*. Leio isto
> como "entidades mapeadas em comum"; **não verifiquei num workspace**. Se a leitura estiver
> errada, as regras 1 e 2 também não se juntam, e o argumento deste caso fica mais forte,
> não mais fraco.

## 3. O cenário — o que teria de ser verdade para se juntarem

Um cenário sintético coerente, construído **de propósito** para atravessar as três famílias
com entidades partilhadas. Nomes: `example.com` (RFC 2606), IPs RFC 5737.

| # | Hora (UTC) | Família | Evento | Regra | Entidades emitidas |
|---|---|---|---|---|---|
| 1 | 08:00:05 | SigninLogs | `j.silva@example.com` entra de RO, dispositivo não conforme, CA `success` | **3** | Account `j.silva`+`example.com` · IP `198.51.100.7` |
| 2 | 08:14:20 | DeviceProcessEvents | em `pc-003.example.com`, conta `j.silva`, `powershell.exe -File …\Temp\a.ps1` | **4** | Host `pc-003`+`example.com` · Account `j.silva`+`EXAMPLE` · Process |
| 3 | 08:31:02 | SecurityEvent 4688 | em `srv-01.example.com`, `schtasks /create … /ru SYSTEM /sc minute`, conta `j.silva` | **1** | Host `srv-01`+`example.com` · Account `j.silva`+`EXAMPLE` · Process |
| 4 | 08:31:03 | SecurityEvent 4698 | `\Updater` registada, principal `S-1-5-18`, registada por `j.silva` | **2** | Host `srv-01`+`example.com` · Account `j.silva`+`EXAMPLE` |

Com este cenário e o agrupamento do Dia 6:

- **3 + 4** juntam-se se `Account` for **o mesmo identificador forte** nos dois. Hoje **não
  é**: a regra 3 mapeia `FullName = j.silva@example.com`; a regra 4 mapeia `Name = j.silva`
  + `NTDomain = EXAMPLE`. São strings diferentes de identificadores diferentes → **dois
  incidentes**.
- **1 + 2** juntam-se (Host e Account iguais).
- **2/4 (pc-003) vs 1/2 (srv-01)**: hosts diferentes; `AllEntities` exige que **todas** as
  entidades mapeadas em comum batam → Host difere → **incidentes separados**, mesmo com a
  mesma conta.

Logo, no melhor cenário, o Sentinel produz **três incidentes** para um ator só. Para
produzir um, há duas vias:

### Via A — normalizar entidades (barata, estrutural)

Na regra 3, mapear `Account` como `Name` + `UPNSuffix` (com `split()`, como os templates
da Microsoft fazem) em vez de `FullName`. Aí `Name = j.silva` bate com a regra 4… mas
`UPNSuffix = example.com` ≠ `NTDomain = EXAMPLE`. A doc lista `Name+UPNSuffix` e
`Name+NTDomain` como identificadores fortes **distintos**. Continuam a não bater por
`AllEntities`.

Restaria `Selected` → `groupByEntities: [Account]` com a entidade reduzida a `Name` — e
`Name` sozinho é **fraco** (doc), e `j.silva` sozinho colide com qualquer `j.silva` de
outro domínio. **A normalização resolve o caso e cria um falso agrupamento.** Não é grátis.

### Via B — correlacionar na query (`join`), e emitir um alerta só

Uma **quinta regra** que não detecta nada novo: junta as três famílias pela conta e pela
janela, e emite um alerta com as entidades de todas. Padrão do Ciclo 4 Dia 6 (bloco 9):

`rules/CASE-04-correlation.kql` — **não testada**, ver §5.

```kusto
let Janela = 2h;
let SignIns =
    SigninLogs
    | where ResultType == "0" and IsInteractive == true
    | where ConditionalAccessStatus != "failure"
    | extend IsCompliant = tostring(DeviceDetail.isCompliant), IsManaged = tostring(DeviceDetail.isManaged)
    | where IsCompliant != "true" and IsManaged != "true"
    | where Location !in ("IE", "PT")
    | extend Name = tostring(split(UserPrincipalName, "@", 0)[0])
    | project SignInTime = TimeGenerated, Name, UserPrincipalName, IPAddress, Location;
let ScriptRuns =
    DeviceProcessEvents
    | where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
    | where ProcessCommandLine has "-File"
    | where ProcessCommandLine has_any (@"\AppData\Local\Temp\", @"\Windows\Temp\", @"\Downloads\")
    | project RunTime = TimeGenerated, Name = AccountName, DeviceName, ProcessCommandLine, ProcessId, ProcessCreationTime;
let TaskRegs =
    SecurityEvent
    | where EventID == 4698
    | parse EventData with * 'TaskName">' TaskName "<" *
    | parse EventData with * 'TaskContent">' TaskContent "</Data>" *
    | where TaskContent contains "&lt;UserId&gt;S-1-5-18&lt;/UserId&gt;"
    | project TaskTime = TimeGenerated, Name = SubjectUserName, Computer, TaskName;
SignIns
| join kind=inner ScriptRuns on Name
| where RunTime between (SignInTime .. SignInTime + Janela)
| join kind=inner TaskRegs on Name
| where TaskTime between (RunTime .. RunTime + Janela)
| project SignInTime, RunTime, TaskTime, Name, UserPrincipalName, IPAddress, Location,
          DeviceName, ProcessCommandLine, Computer, TaskName
```

Entidades desta quinta regra: Account (`Name`+`UPNSuffix` da identidade), IP, **dois**
Hosts (`DeviceName`, `Computer`), Process. Um alerta, um incidente, três famílias.

O preço: `join` **por `Name` sozinho** — a mesma fraqueza da Via A, agora dentro da query.
`u3` no endpoint e `j.silva` na identidade **nunca** se juntam; a query só funciona se a
organização usar o mesmo prefixo de UPN como nome de conta local. É uma **hipótese sobre a
organização**, não sobre o Sentinel — e vai escrita na `description`.

## 4. O que a evidência sustenta

- Com as fixtures existentes, as quatro regras produzem incidentes **separados** por família
  — porque as entidades não coincidem, e isso está medido nas próprias fixtures.
- Regras 1 e 2 partilham Host+Account nas fixtures e caem no mesmo incidente sob a leitura
  literal da doc de agrupamento.
- A correlação entre famílias exige **ou** normalização de identificadores de conta (com
  risco de agrupar contas homónimas) **ou** uma regra de `join` (com a mesma hipótese
  embutida).

## O que a evidência NÃO sustenta

- Que a query de `join` **compila num Kusto real** — testada só no avaliador local (4/4),
  cuja semântica de `join` e `between` é a minha leitura da doc.
- Que `AllEntities` ignora entidades presentes num alerta e ausentes noutro — leitura da
  doc, não observação.
- Que numa organização real `AccountName` (endpoint) = prefixo do UPN (identidade) =
  `SubjectUserName` (Windows). É a hipótese que decide tudo e **não é de telemetria**: é de
  convenção de identidade — a mesma conclusão do CASE-03 §4 (*"o que separa H1 de H2 não
  está na telemetria"*).

## 5. Limitações

- ~~`join` fora do avaliador local.~~ **Dia 7.1 (22/09, mesma sessão):** o avaliador
  cresceu com `let`, `join kind=inner on <col>`, `between`, `project` com alias e
  `extend … split(…)`; `tools/run_case.py` corre a query contra `tools/fixtures-case04.json`:

  ```text
  A  cenário do §3, j.silva nas 3 famílias em 31 min      1 linha   PASS
  B  universos originais (u3 / admmig / j.silva)            0 linhas  PASS  <- o §2, em código
  C  mesma conta, tarefa 3h depois (janela 2h)              0 linhas  PASS
  D  homónimo: j.silva@example.com vs j.silva de CONTOSO    1 linha   PASS  <- FALSO POSITIVO por desenho
  ```

  O caso **D** é o preço da Via B escrito em fixture: o `join` por `Name` junta contas
  homónimas de domínios diferentes. Não é bug do avaliador; é a hipótese embutida a falhar
  exactamente onde o §3 disse que falharia.
- O avaliador continua a **não** ser Kusto: `join` só por uma coluna, sufixo `1` em colisão
  (como o Kusto), sem `summarize`, sem `mv-expand`, sem regex.
- O cenário do §3 é construído para correlacionar; não veio de nenhum dos três casos
  originais. Está rotulado.
- Portal do Defender (obrigatório 31/03/2027): o motor de correlação do XDR tem regras
  próprias que este modelo não cobre.

## 6. MITRE ATT&CK — o que o incidente único contaria

| Passo | Técnica | Regra |
|---|---|---|
| Sign-in de dispositivo não conforme, país fora da lista | T1078.004 Valid Accounts: Cloud · T1556.006 MFA | 3 |
| Script em pasta temporária via `-File` | T1059.001 PowerShell | 4 |
| Tarefa agendada como SYSTEM, alta frequência | T1053.005 Scheduled Task | 1, 2 |

Três tácticas — Initial Access → Execution → Persistence — que só aparecem **como sequência**
se o incidente for um. Em três incidentes, cada analista vê uma táctica e nenhum vê o ataque.

## 7. Confiança

- **Alta** que as fixtures actuais não se correlacionam (medido).
- **Alta** que a correlação depende da convenção de identificadores (doc + fixtures).
- **Média** na leitura de `AllEntities` com entidades assimétricas (doc, sem workspace).
- **Baixa** em qualquer número de incidentes num ambiente real.

---

## MARCUS REFLECTION

```text
MARCUS REFLECTION: PENDING
```

Pergunta de entrevista deste caso — só para `ENTREVISTA.md` quando sair em voz alta, sem ler:

> *"Você tem detecção de identidade, de endpoint e de servidor. Um ator passa pelos três. Quantos incidentes o seu SIEM abre — e o que decide isso?"*
