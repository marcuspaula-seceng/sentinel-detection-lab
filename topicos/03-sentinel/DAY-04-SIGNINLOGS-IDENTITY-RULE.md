# Ciclo 5 · Dia 4 — Regra de identidade em `SigninLogs`: a primeira com colunas `dynamic`

**22/09/2026** · o CASE-03 vira regra, e o tipo de uma coluna corrige o Ciclo 4.

---

## Rótulo de claim

```text
SYNTHETIC LAB

Motor:        nenhum motor Kusto; avaliador local (agora com !=, in/!in, bool, extend/tostring)
Tenant:       NENHUM tenant Entra; NENHUM workspace
Host:         nada instalado
Dados:        12 fixtures; 6 são as linhas do dataset sintético do Ciclo 4 (DAY-02),
              domínio example.com (RFC 2606), IPs RFC 5737
Execução:     python tools/run_tests.py  ->  32/32 nas três regras, exit 0
```

## 1. O que a regra 3 detecta — e o que deixa para a correlação

Do CASE-03, achados 3 e 4: *a sessão que satisfez MFA vinha de outro país e de um
dispositivo não conforme, e a política de dispositivo conforme ficou `notApplied`.*

Isso é **uma linha** de `SigninLogs`. A regra vê essa linha:

```text
sucesso interactivo  +  dispositivo nem conforme nem gerido  +  país fora da lista
+  Conditional Access não bloqueou (success ou notApplied)
```

O que **não** faz, por desenho: "três falhas seguidas de sucesso" (achado 1) é agregação
(`summarize`) — fica para o Dia 6/CASE-04. Uma regra, um comportamento.

## 2. Templates reais — o que copiei e o que não

`Solutions/Microsoft Entra ID/Analytic Rules/`, via `gh api`:

| Template | O que ensinou |
|---|---|
| `MFASpammingfollowedbySuccessfullogin.yaml` v1.0.4 | `connectorId: AzureActiveDirectory` · `dataTypes: SigninLogs` · `tostring(DeviceDetail.operatingSystem)` para ler `dynamic` · entidade `Account` por `FullName` + `Name` + `UPNSuffix` (com `split`) · `IP` por `Address` |
| `FailedLogonToAzurePortal.yaml` | **`ResultType in ("0", "50125", "50140")`** — comparado como **string** · segundo `dataTypes`: `AADNonInteractiveUserSignInLogs` |

**Copiei:** conector, forma de ler `DeviceDetail`, mapeamento `FullName`/`Address`,
`kind`/`status`.
**Não copiei:** `split()` para `Name`/`UPNSuffix` — fora do subconjunto; `FullName` é o
que os templates da MS também usam.

## 3. DELTA ao Ciclo 4 — `ResultType` é string

A página oficial de `SigninLogs` (Dia 1) diz `ResultType string`. Os templates da Microsoft
comparam com `"0"`. As queries do `04-entra-iam/DAY-06-IDENTITY-KQL.md` (blocos 1, 2, 3, 9)
usam **`ResultType != 0`** e **`== 0`** — inteiro.

No Graph (Ciclo 4) o campo era `status.errorCode` **Int32**, e a lição *"errorCode 0 ≠
entrou"* está certa. Mas ao passar para a tabela do Sentinel o tipo mudou e o Ciclo 4 não
deu por isso — porque nunca executou contra a tabela.

```text
A licao sobreviveu a tradução. O tipo não.
```

O DAY-06 **não foi editado** (Ciclo 4 está fechado tecnicamente). Fica aqui como delta,
com a fixture "TIPO" a provar a consequência: `ResultType` numérico não casa `"0"`.

## 4. IMPLEMENTAR

`rules/marcus_signin_noncompliant_device_outside_allowed_countries.sentinel.yaml`:

```kusto
SigninLogs
| where ResultType == "0"
| where IsInteractive == true
| where ConditionalAccessStatus != "failure"
| extend IsCompliant = tostring(DeviceDetail.isCompliant)
| extend IsManaged = tostring(DeviceDetail.isManaged)
| where IsCompliant != "true" and IsManaged != "true"
| where Location !in ("IE", "PT")
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location,
          ConditionalAccessStatus, IsCompliant, IsManaged
```

`IE`/`PT` são a lista do CASE-03. Em produção é uma **watchlist**, não uma constante.

## 5. O avaliador cresceu — de novo só o necessário

`!=` · `in`/`!in` com lista de literais · `true`/`false` · `extend Col = tostring(Src.field)`
com **um** nível de acesso a `dynamic` (a fixture traz o `dict`). Regras seguidas:

- `tostring(null)` → `""` (como o Kusto); campo ausente → `""`;
- comparar `null` com `==`, `!=`, `in`, `!in` → **falso** (a linha não passa) — é assim que
  o Kusto trata null em predicados.

## 6. TESTAR / QUEBRAR — as 12 fixtures

```text
=> 3 TP / 9 TN / 0 FAIL
```

| # | Fixture | Veredito | O que prova |
|---|---|---|---|
| 1 | DAY-02 #1 — 50126, IE | NO | falha não é sucesso |
| 2 | DAY-02 #4 — `0` mas CA `failure` | NO | a política travou; não há sessão |
| 3 | **DAY-02 #5 — a sessão do CASE-03** | **MATCH** | a regra apanha o que o caso descreve |
| 4 | DAY-02 #6 — mesma sessão, Graph Explorer | MATCH | cada app é uma linha → *event grouping* decide 1 ou 2 alertas |
| 5 | DAY-02 #7 — `svc-sync`, não interactivo | NO | identidade não-humana fora, por desenho |
| 6 | DAY-02 #8 — `a.costa`, IE, conforme | NO | o **fio B** do CASE-03 é invisível a `SigninLogs` inteiro — vive em `AuditLogs` |
| 7 | igual ao positivo, de PT | NO | viagem dentro da lista |
| 8 | RO, portátil da empresa | NO | dispositivo certo |
| 9 | **gerido mas não conforme** | NO | fronteira: exige que ambos falhem; decisão declarada |
| 10 | **`DeviceDetail` vazio** | **MATCH** | telemetria em falta vira alerta — **falso positivo por desenho** |
| 11 | `ResultType` **numérico** | NO | a comparação é de tipo — o delta do §3 em código |
| 12 | `Location` null | NO | `!in` sobre null é falso — lacuna simétrica à #10 |

As fixtures 10 e 12 são o par mais importante: **a mesma ausência de telemetria produz
alerta num campo e silêncio noutro.** Nenhum dos dois é neutro.

## 7. O que a evidência sustenta

- A regra reproduz o veredito do CASE-03 sobre o dataset do Ciclo 4 sem alterar uma linha dele.
- Conector, tipo de `ResultType`, leitura de `dynamic` e entidades batem com templates
  publicados pela Microsoft.
- O comportamento com null/ausente está escrito em fixture, não em prosa.

## O que a evidência NÃO sustenta

- Que `IsInteractive == true` e `DeviceDetail.isCompliant` têm exactamente estes nomes e
  tipos **na tabela** — `IsInteractive bool` e `DeviceDetail dynamic` estão na página oficial;
  os sub-campos `isCompliant`/`isManaged` vêm do metadata do Graph (Ciclo 4), **não** da
  página da tabela.
- Que a query compila num Kusto real.
- Qualquer coisa sobre volume de falsos positivos numa organização real.

## 8. Limitações

- Lista de países hard-coded; `AADNonInteractiveUserSignInLogs` não coberta; `split()`
  não usado, logo sem `Name`+`UPNSuffix` (identificador forte) — só `FullName`.
- `DeviceDetail` ausente dispara. A alternativa (`isnotempty(DeviceDetail)`) silenciaria
  exactamente o caso em que um atacante usa um cliente que não reporta dispositivo. Escolhi
  ruído sobre silêncio; está declarado.

## Próximo passo

**Dia 5:** regra de endpoint sobre `DeviceProcessEvents` a partir do CASE-01 (Ciclo 2) —
as queries já existem; a tabela tem as mesmas colunas. Ver se ASIM (`imProcessCreate`)
entra como fonte, como a doc recomenda.

---

## MARCUS REFLECTION

```text
MARCUS REFLECTION: PENDING
```

Pergunta de entrevista deste dia — só para `ENTREVISTA.md` quando sair em voz alta, sem ler:

> *"A telemetria de dispositivo não veio. A sua regra dispara ou fica calada? Por quê?"*
