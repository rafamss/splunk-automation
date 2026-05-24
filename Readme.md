# Splunk Automation Toolkit

Ferramentas de automação para ambientes Splunk Enterprise: instalação, configuração, geração de logs para laboratório e boas práticas operacionais.

Criado para profissionais de segurança, instrutores e times de SOC que precisam subir ambientes rapidamente, gerar dados realistas para treinamento e padronizar deployments.

---

## Estrutura do Repositório

```
splunk_automation/
├── tools/                        # Ferramentas operacionais
│   └── log_generator.py          # ✅ Gerador multi-formato de logs
├── scripts/                      # Automação de instalação (em desenvolvimento)
│   ├── download.sh
│   ├── install.sh
│   └── configure.sh
├── apps/                         # Splunk apps prontas para deploy (em desenvolvimento)
│   └── deployment_client/
├── docs/                         # Documentação detalhada (em desenvolvimento)
│   ├── prerequisites.md
│   ├── installation-guide.md
│   └── version-history.md
├── config.example.env            # Variáveis de configuração (em desenvolvimento)
└── README.md
```

---

## Log Generator

Gerador de logs realistas para laboratórios Splunk, treinamentos de SOC e simulações de incidentes. Suporta seis formatos, injeta eventos suspeitos configuráveis e opera em modo batch ou streaming contínuo.

**Sem dependências externas** — roda com Python 3.10+ puro.

### Formatos suportados

| Formato | Flag | Descrição |
|---|---|---|
| Windows Event Log | `windows` | XML com EventIDs reais (4624, 4625, 4688, 4720, 1102, etc.) |
| Syslog RFC 3164 | `syslog` | PRI calculado, facility/severity, apps como sshd, cron, sudo |
| Fortinet FortiGate | `fortinet` | Formato key=value nativo com campos UTM e IPS |
| Cisco ASA | `cisco_asa` | Syslog com message IDs padrão (%ASA-x-xxxxxx) |
| Check Point | `checkpoint` | Formato LEA/Log Exporter com blades de segurança |
| Palo Alto Networks | `paloalto` | CSV nativo (TRAFFIC, THREAT, URL filtering) |

### Uso rápido

```bash
# Gerar 500 logs Windows com 10% de eventos suspeitos
python3 tools/log_generator.py -t windows -c 500 -s 10

# Syslog contínuo a 20 eventos/seg com bursts a cada 30s
python3 tools/log_generator.py -t syslog -m continuous -r 20 --burst --burst-size 100

# Mix de firewalls gravando em arquivo
python3 tools/log_generator.py -t fortinet,cisco_asa,checkpoint,paloalto -c 1000 -o logs.txt

# Cenário de ataque: 25% de eventos suspeitos, streaming contínuo
python3 tools/log_generator.py -t windows,syslog -m continuous -r 15 -s 25
```

### Parâmetros

| Parâmetro | Padrão | Descrição |
|---|---|---|
| `-t, --type` | — | Tipo(s) de log, separados por vírgula |
| `-c, --count` | `100` | Quantidade de eventos no modo single |
| `-m, --mode` | `single` | `single` (batch) ou `continuous` (streaming) |
| `-r, --rate` | `5` | Eventos por segundo no modo contínuo |
| `--burst` | off | Ativa picos periódicos de eventos |
| `--burst-size` | `50` | Eventos por burst |
| `--burst-interval` | `30` | Segundos entre bursts |
| `-s, --suspicious-rate` | `5` | Porcentagem de eventos suspeitos injetados |
| `-o, --output` | stdout | Caminho do arquivo de saída |

### Eventos suspeitos injetados

Os eventos maliciosos são injetados no fluxo normal com marcação `<!-- SUSPICIOUS -->` ou `[SUSPICIOUS]` para facilitar a localização durante as aulas. Tipos incluem:

**Windows:** tentativas de brute force (4625), criação de contas suspeitas (4720), privilege escalation (4672), limpeza de audit log (1102), execução de ferramentas ofensivas como mimikatz, certutil, powershell encoded, psexec, instalação de serviços maliciosos (4697), adição a grupo Administrators (4732).

**Linux:** SSH failed login de IPs maliciosos, sudo por usuários não autorizados, reverse shells, comandos de reconhecimento (nmap, cat /etc/shadow), persistência via crontab, exfiltração via scp.

**Firewalls:** conexões de/para IPs de threat intelligence, port scans, assinaturas IPS/IDS, comunicação C2, exfiltração de dados (alto volume de bytes), acesso a URLs maliciosas, detecção de malware (Cobalt Strike, Emotet, TrickBot), violações de política de URL filtering.

---

## Roadmap

### Instalação automatizada (`scripts/`)

Reescrita dos scripts de download e instalação com suporte a Splunk 9.x, validação SHA-512, detecção automática de distro e arquitetura (x86_64/ARM64), sem credenciais hardcoded.

- [ ] `download.sh` — download parametrizado com validação de integridade
- [ ] `install.sh` — instalação com criação de usuário, systemd unit, hardening básico
- [ ] `configure.sh` — pós-instalação (SSL, limites, indexes, outputs.conf)

### Splunk Apps (`apps/`)

Apps prontas para deploy via Deployment Server.

- [ ] `deployment_client` — deploymentclient.conf parametrizado
- [ ] `base_inputs` — inputs.conf padrão para Linux e Windows
- [ ] `base_outputs` — outputs.conf com load balancing

### Documentação (`docs/`)

- [ ] Pré-requisitos e matriz de compatibilidade
- [ ] Guia passo a passo de instalação
- [ ] Histórico de versões e URLs de download

### CI/CD (`.github/workflows/`)

- [ ] ShellCheck para validação de scripts
- [ ] Linting Python (ruff/flake8)
- [ ] Testes automatizados do log generator

---

## Requisitos

- **Python** 3.10+ (log generator)
- **Bash** 4+ (scripts de instalação)
- **Sistemas suportados:** RHEL/CentOS 7+, Ubuntu 18.04+, Debian 10+

---

## Licença

GPL-3.0 — veja [LICENSE](LICENSE) para detalhes.
