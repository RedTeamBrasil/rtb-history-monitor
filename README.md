# RTB History Monitor

Extensão do Burp Suite para monitoramento de cobertura de endpoints durante testes de intrusão. Rastreia quais URLs/métodos já foram analisados, facilitando o controle do escopo testado ao longo de uma sessão.

---

## Requisitos

- Burp Suite (Community ou Pro)
- Jython standalone (2.7.x) configurado em **Extender > Options > Python Environment**

---

## Instalação

1. Faça o download do [Jython standalone JAR](https://www.jython.org/download) e configure-o no Burp Suite em **Extender > Options > Python Environment**.
2. No Burp Suite, vá em **Extender > Extensions > Add**.
3. Selecione **Extension Type: Python**.
4. Aponte para o arquivo `main.py` deste repositório.
5. Clique em **Next**. A aba **Scope Monitor - Custom** aparecerá na barra principal do Burp.

---

## Funcionalidades

### Monitor de Requisições

A aba principal exibe uma tabela com todas as requisições capturadas contendo as colunas:

| Coluna    | Descrição                                              |
|-----------|--------------------------------------------------------|
| Checked   | Indica se o endpoint foi analisado (`True` / `False`)  |
| URL       | URL sem query string (apenas scheme + host + path)     |
| Method    | Método HTTP (GET, POST, etc.)                          |
| Time      | Timestamp da primeira captura                          |
| Tags      | Tags atribuídas manualmente ao endpoint                |

Requisições duplicadas (mesma URL + método) são consolidadas em uma única entrada — a entrada existente é atualizada em vez de criar um novo registro.

### Filtros de Visualização

- **Show All** — exibe todos os endpoints capturados.
- **Show New Only** — exibe apenas endpoints ainda não analisados.
- **Show Tested Only** — exibe apenas endpoints marcados como analisados.

### Colorização na Aba Proxy

Quando ativado, o monitor coloriza as requisições diretamente na aba **Proxy > HTTP History**:

- **Verde** — requisição marcada como analisada.
- **Vermelho** — requisição ainda não analisada.

### Sistema de Tags

Tags podem ser atribuídas a um endpoint para classificação semântica durante o teste. As tags pré-definidas são:

- `Login`
- `Logout`
- `MFA`
- `PII`

Tags são aplicadas via menu de contexto (botão direito) tanto na tabela do monitor quanto na aba **Proxy > HTTP History**.  
Múltiplas tags são armazenadas separadas por `|` e persistidas no arquivo de estado.

### Menu de Contexto

Clique com o botão direito sobre uma ou mais linhas na tabela do monitor para acessar:

- **Mark Requests as Analyzed** — marca selecionados como analisados.
- **Mark Requests as NOT Analyzed** — reverte o status para não analisado.
- **Send Request to Repeater** — envia a requisição para a aba Repeater.
- **Delete request** — remove a entrada do monitor.
- **Tags** — submenu para aplicar uma tag ao endpoint selecionado.

O mesmo menu de contexto (Mark / Tags) também está disponível ao clicar com o botão direito em requisições na aba **Proxy > HTTP History**.

### Ferramentas Monitoradas

O monitor captura tráfego originado apenas das seguintes ferramentas do Burp:

- **Proxy**
- **Repeater**
- **Target**

### Filtro por Extensão e MIME

Requisições para recursos estáticos são ignoradas automaticamente. Os padrões padrão são:

**Extensões ignoradas:**
`.gif`, `.png`, `.js`, `.woff`, `.woff2`, `.jpeg`, `.jpg`, `.css`, `.ico`, `.m3u8`, `.ts`

**MIME types ignorados:**
`gif`, `script`, `jpeg`, `jpg`, `png`, `video`, `mp2t`

As listas são configuráveis na aba **Config > General** e são persistidas entre sessões.

---

## Configurações

### Aba General

| Opção                                              | Descrição                                                                 |
|----------------------------------------------------|---------------------------------------------------------------------------|
| Monitor ON/OFF                                     | Ativa ou desativa a captura de requisições                                |
| Autostart Scope Monitor                            | Inicia o monitor automaticamente ao carregar a extensão                   |
| Repeater request automatically marks as analyzed   | Requisições enviadas pelo Repeater são marcadas como analisadas            |
| Follow Burp Target In Scope rules                  | Monitora apenas URLs dentro do escopo definido em **Target > Scope**       |
| Color request in Proxy tab if analyzed             | Coloriza de verde requisições analisadas na aba Proxy                     |
| Color request in Proxy tab if NOT analyzed         | Coloriza de vermelho requisições não analisadas na aba Proxy              |
| Ignore extensions / Ignore mime types              | Listas de extensões e MIME types a ignorar                                |

### Aba Import/Export

| Opção        | Descrição                                                        |
|--------------|------------------------------------------------------------------|
| State file   | Caminho do arquivo para salvar/carregar o estado do monitor      |
| Save now     | Exporta o estado atual para o arquivo configurado                |
| Load now     | Importa um estado previamente salvo                              |
| Auto save    | Salva automaticamente a cada ~3 minutos                          |

O arquivo de estado é um CSV simples com os campos: `analyzed`, `url`, `method`, `date`, `tags`.

### Push para o red-burp-watchdog

Na aba **Config**, a opção **Push request/response to Watchdog listener** envia cada par
request/response (de Proxy/Repeater/Target, dentro do escopo do Burp) em tempo real para um
listener local — o modo push da skill `red-burp-watchdog` (ZCode), que os salva no formato do
inventário de triagem (`traffic/`, `events.jsonl`, `endpoints.json`).

- **Liga/desliga independente** do ON/OFF do monitor: o push tem o próprio checkbox e funciona
  mesmo com o monitor desligado (respeitando sempre o escopo do Burp e a ferramenta de origem).
  **Padrão desativado** (opt-in): marque o checkbox para ativar; o estado é persistido.
- **Listener URL** (padrão `http://127.0.0.1:8787/ingest`): endereço do listener; ajuste a porta
  se necessário e clique em **Save**.
- O contador `push: N ok / N falha / N descartado` mostra o resultado dos envios.
- Política de tamanho (protege o heap do Burp): corpos completos até 512KB; entre 512KB e 2MB
  o response vai truncado (headers completos + início do corpo, marcado como truncado); acima
  de 2MB o item é descartado. Extensões/MIMEs estáticos ignorados nas listas existentes também
  não são enviados.
- O listener fica em `~/.zcode/skills/red-burp-watchdog/scripts/burp_watchdog_listener.py`
  (`python3 burp_watchdog_listener.py --dir <projeto>/burp-watchdog`).
- Configurações persistidas nas extension settings: `PUSH_ENABLED`, `PUSH_URL`.

---

## Uso Típico em Pentest

1. Configure o escopo em **Target > Scope** e ative **Follow Burp Target In Scope rules**.
2. Navegue na aplicação alvo via Proxy.
3. Na tabela do monitor, use **Show New Only** para identificar endpoints ainda não testados.
4. Ao testar um endpoint, envie-o ao Repeater (que marca automaticamente como analisado) ou marque manualmente via menu de contexto.
5. Aplique tags (`Login`, `MFA`, `PII`, etc.) para anotar a natureza de cada endpoint.
6. Use **Save now** periodicamente ou deixe o Auto Save ativo para não perder o progresso.

---

## Créditos

Este projeto é um fork com modificações de [**Burp Scope Monitor**](https://github.com/Regala/burp-scope-monitor), desenvolvido originalmente por **[Regala](https://github.com/Regala)**.
