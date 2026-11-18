# Execução do piloto VPN — 16/11/2026

## Estado efetivo

Instalado e em execução na Oracle em `/opt/hermes-security-vpn`, container
`hermes-security-vpn`, com estado persistente exclusivo. Imagem ARM64 wg-easy
15.5.0 fixada por digest, conferida igual no Mac e na Oracle.

O servidor está saudável e publica **UDP 51820** no Docker. O painel HTTP está
publicado **somente em 127.0.0.1:51821**, para acesso por túnel SSH.
Configuração inicial concluída; a senha não está no ambiente do container
normal. O `INIT_ENABLED` da imagem permanece como flag padrão, sem credenciais.
A senha inicial continua em arquivo local protegido no host, para o operador.

**O túnel externo de teste passou em 16/11/2026, às 17:03:41 BRT.** Após o
operador informar a criação da entrada UDP 51820 no NSG, o teste desde o Docker
do Mac completou handshake, DNS, HTTPS e confirmou saída por `132.145.178.32`.
As 15 verificações passaram e a remoção do peer temporário foi confirmada.
Em seguida, o operador confirmou que a VPN funciona no Mac e no celular.
Para o Mac, forneceu saída do curl e captura do navegador mostrando
`132.145.178.32`; para o celular, confirmou o funcionamento por mensagem.
Isso valida a conexão básica dos clientes. A etapa seguinte concluiu acesso
administrativo com VPN ativa, backup cifrado/restauração isolada e recuperação
automática do processo. O operador também confirmou o teste comparativo IPv6
do iPhone: sem VPN abriu, com VPN não abriu, IPv4 continuou funcionando e IPv6
voltou após desligar a VPN. DNS, cobertura em outras redes, desempenho
sustentado e reboot da VM continuam com pendências.

Durante a atualização dos registros após essa confirmação, o Mac apresentou
rota para `132.145.178.32` pela interface `utun6`, e TCP 22 expirou em 4 segundos.
Isso é compatível com o bloqueio já configurado do IP público da VM para peers.
A sincronização inicial foi interrompida. O acesso foi resolvido depois com
`admin-ssh.py`, que vincula somente o socket SSH à interface física do Mac.
SSH e painel HTTP 200 foram testados com a VPN ativa, sem exceção no firewall
dos peers nem mudança de rotas globais. A sincronização dos documentos pôde ser
retomada por esse caminho. O SSH comum continua sujeito ao bloqueio do túnel.

## Ajustes prioritários executados após conexão dos clientes

- **Administração:** SSH e painel funcionaram com rota VPN ativa em `utun6`,
  usando `nc -b en0` apenas para a conexão administrativa. O teste encerrou seu
  próprio túnel temporário e preservou as sessões do operador.
- **Backup:** age v1.3.2 ARM64, com digests oficiais fixados. Identidade privada
  gerada e mantida no Mac (0600); somente destinatário público enviado à VM.
  Snapshot SQLite consistente, arquivo claro apenas em RAM, cópias cifradas
  na Oracle e no Mac. Alteração de um byte do arquivo cifrado foi rejeitada.
- **Restauração:** duas cópias foram verificadas em volume/container descartável,
  sem rede e sem portas. Banco íntegro, identidade WireGuard restaurada e painel
  respondendo. Todos os recursos temporários do ensaio foram removidos.
- **Recuperação automática:** `unless-stopped` aplicado no Compose e runtime.
  Queda controlada do processo Node causou reinício automático em **11,57 s**;
  identidade, dois peers e integridade SQLite preservados. Nenhuma recuperação
  manual foi necessária. Containers Hermes e INPUT do host permaneceram iguais.
- **Mac após recuperação:** saída IPv4 da VPN nativa confirmou `132.145.178.32`.
- **DNS/IPv6 básico:** resolvedor principal configurado como 1.1.1.1/1.0.0.1.
  Um destino IPv6 literal respondeu pela interface física vinculada explicitamente,
  mas não pela rota padrão com a VPN ativa. Isso valida o bloqueio IPv6 nesse
  caminho do Mac; não cobre o celular, outras redes ou vazamento DNS por pacotes.
- **iPhone, confirmação do operador:** o endpoint somente IPv6 abriu sem VPN,
  não abriu com VPN, e voltou a abrir após desligá-la. IPv4 funcionou com VPN.
  Esse controle antes/depois valida o bloqueio IPv6 no cenário relatado, sem
  constituir captura de pacotes ou auditoria de todos os aplicativos. O resultado
  não reexplicitou o tipo da rede, o IP IPv4 ou o estado da Retransmissão Privada;
  esses detalhes não são presumidos. Registro em `iphone-ipv6-user-validation.json`.
- **Reteste Wi-Fi do iPhone:** após relatar IPv6 inicialmente visível e depois
  ausente, o operador confirmou que a nova requisição ao endpoint IPv6 não
  respondeu, enquanto IPv4 funcionou. O reteste é compatível com bloqueio IPv6
  no Wi-Fi. A causa da observação inicial não foi determinada; cache ou transição
  são hipóteses, não diagnósticos comprovados. Não foi medida a janela de transição.
- **Teste Docker:** agora recusa execução com VPN ativa no Mac, evitando túnel
  sobre túnel e diagnósticos ambíguos. O teste do aplicativo nativo é separado.

**Reboot real aprovado em 17/11:** SSH com novo boot observado em 45,94 s;
Hermes e WireGuard prontos automaticamente em 62,64 s. Dois peers preservados,
15 verificações externas aprovadas e perfil nativo do Mac confirmado com saída
`132.145.178.32`. O estado inicial desconectado do Mac foi restaurado. O iPhone
não foi retestado nesta rodada. Reinício isolado do daemon Docker continua sem
ensaio. Naquela etapa não havia monitor de tráfego; o coletor systemd foi
implantado depois, conforme a atualização abaixo. Não houve atualização
automática de imagem.
Evidências: `evidence/reboot-20261117T235838Z.json` e
`evidence/tunnel-20261118T000220Z.json` (timestamps dos arquivos em UTC).
Procedimentos e custódia da chave estão em `OPERACAO.md`.

## Criado e preservado

- Branch `codex/oracle-security-vpn` no projeto `my-vpn`; sem commit nesta etapa.
- Compose independente, política de rede no namespace, bootstrap privado,
  testes com peer descartável e auditoria sanitizada.
- Volume Docker `hermes-security-vpn_wireguard` na área atual do Docker.
  **Nenhum block volume adicional OCI**, nova VM ou alteração no CoBudget.
- Estado novo gerado na Oracle; nenhum perfil/Vault antigo foi migrado. Na etapa
  de recuperação, backups cifrados da VM foram copiados para o Mac. A identidade
  privada age permaneceu no Mac; nenhum segredo foi exibido ou versionado.
- Bootstrap Ansible antigo, SSH, políticas globais e serviços existentes
  preservados. Docker acrescenta as redes/NAT específicos do novo projeto.
- No Mac, o container VPN e suas redes de teste foram removidos ao final;
  o volume de estado de teste foi preservado. Hermes não foi interrompido.

## Executado e aprovado

| Verificação | Evidência/resultado |
| --- | --- |
| Arquitetura e imagem | ARM64 em ambos; digest `sha256:071f79a639e9361123a5e57733107320207b844ddbbd92dfa6962f541fe8aac8` |
| Interface kernel WireGuard | Criada sem `SYS_MODULE`, sem `/lib/modules` e sem modo privileged |
| Túnel local de controle | Cliente Docker em rede interna, sem saída direta; handshake, DNS e HTTPS passaram |
| Túnel de controle na Oracle | 15 verificações aprovadas em duas rodadas de aproximadamente 9 s cada |
| IP de saída da Oracle | `132.145.178.32`, observado por HTTPS no cliente pelo túnel |
| Bloqueios reais | Contadores de DROP aumentaram para host privado, metadados, redes Docker/Hermes, endereço do servidor VPN, outro endereço de peer e IPs públicos protegidos |
| DNS | Consulta a 1.1.1.1 aprovada; TCP/UDP 53 para resolvedor não autorizado descartados |
| Revogação | Remoção de peer temporário interrompeu sua conectividade DNS |
| Painel por SSH desde o Mac | HTTP 200 no túnel temporário; túnel de teste encerrado sem login |
| Recriação e restart do container | Estado e interface recuperados, regras reinstaladas, bateria interna aprovada novamente |
| Administração | UI em loopback; senha de bootstrap ausente do ambiente normal |
| Separação do Hermes | Conexão ao painel VPN bloqueada; alvo controlado do Hermes continuou respondendo HTTP 200 |
| SSH e INPUT do host | Regras INPUT exatamente iguais ao inventário anterior; SSH 22 preservado |

Bloqueio entre peers foi testado por tráfego para outro endereço do prefixo,
com descarte confirmado antes do encaminhamento; não foram criados dois
dispositivos físicos para esse teste. IPv6 desativado foi conferido no servidor;
isso não substitui teste de vazamento nos clientes reais.

## Consumo observado

Limites configurados: **0,25 CPU, 512 MiB, 128 processos**. Host compartilhado
com Hermes: 1 CPU / cerca de 6 GB. Nenhuma mudança nos limites do Hermes.

- RAM atual em repouso: **44,5 MiB**; pico do container observado: **56,7 MiB**.
- CPU em repouso: **0,11% de um núcleo**, em amostra de **10,05 segundos**.
- Estado persistente após ensaios: **98.977 bytes**, aproximadamente 97 KiB.
- Imagem local: cerca de **82 MB** (tamanho informado pelo Docker).
- Ensaios da VPN não executaram chamadas ao modelo de IA do Hermes.

Essas medidas cobrem inicialização e requisições curtas. Não medem streaming,
velocidade sustentada, concorrência, impacto do Hermes trabalhando ao mesmo
tempo ou consumo faturável mensal. O teto de CPU pode limitar a velocidade.

## Falha externa inicial e resolução posterior

Atualização de 16/11, 17:03:41 BRT: a tentativa
`tunnel-20261116T200341Z.json` passou nas 15 verificações pelo endpoint público.
O relatório contém handshake autenticado, IP de saída da Oracle e
`temporary_peer_removed: true`. A regra DNAT passou a receber pacotes externos.
A regra OCI foi criada pelo operador; não foi feita auditoria da associação
NSG/VNIC por API. Os parágrafos seguintes registram o diagnóstico anterior.

Dois testes do endpoint público a partir de um cliente WireGuard descartável
no Docker do Mac falharam. Na rodada final, o servidor não registrou handshake
do peer, e sua remoção foi confirmada pelo próprio script.

A regra DNAT UDP 51820 da Oracle permaneceu em **zero pacotes**, inclusive
após três datagramas diagnósticos enviados diretamente do Mac ao mesmo endpoint.
O socket UDP está ativo e o túnel interno funciona. Isso aponta para bloqueio
antes do encaminhamento Docker; **a hipótese principal é a entrada OCI**, mas
sem inventário do NSG/security list não é possível atribuir a causa com certeza.

Configuração de entrada orientada ao operador e posteriormente informada como criada:

1. Selecionar a instância pelo IP `132.145.178.32`, hostname `security-lab-vnic`,
   Ashburn AD-2. O display name inventariado é `instance-20260614-1200`.
2. Na VNIC primária, verificar os NSGs associados e security lists da subnet.
3. Adicionar regra **stateful de entrada UDP**, origem `0.0.0.0/0`, porta de
   origem **All**, porta de destino **51820**. Essa origem permite mudança de
   rede/IP do celular; a autenticação dos peers continua por chave WireGuard.
4. Não abrir TCP 51821, nem modificar SSH 22. Não aplicar à VNIC do CoBudget.

Modelo de regra NSG revisável em `config/oci-nsg-ingress.json`; nenhum OCID foi
presumido e o JSON não foi aplicado. Preferir NSG da VNIC do laboratório a uma
regra indiscriminada em subnet compartilhada. Seguir a
[documentação OCI de regras de segurança](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securityrules.htm).

Para repetir o teste, no Mac, execute uma única instância por vez:

```sh
cd /Users/guga/workspace/my-vpn/oracle-security-lab
python3 scripts/test-tunnel.py --server-ssh ubuntu@132.145.178.32
```

O comando cria somente um peer de teste no endereço reservado
`10.66.77.254/32`, remove-o ao final e não configura o WireGuard do macOS.
Não alocar esse endereço a um dispositivo real.

## Problemas encontrados e corrigidos durante a preparação

- O backend iptables legado da imagem falhou ao criar NAT no kernel do Docker
  do Mac. O entrypoint passou a selecionar os binários nft disponíveis na
  própria imagem; o NAT e o filtro foram testados nos dois ambientes.
- O verificador precisou esperar a interface inicializar e atender ao formato
  de resposta DNS exigido pelo Node 24. Os testes positivos subsequentes passaram.
- A limpeza do primeiro teste público tentou remover o peer no Docker local.
  A rotina foi corrigida para usar o mesmo destino SSH do teste. O peer
  temporário reservado foi removido na Oracle e uma segunda rodada confirmou
  a limpeza remota, inclusive com falha de conexão. Auditoria final: zero peers.
- Em 16/11 às 17:02–17:03 BRT, três tentativas do operador coincidiram com a
  execução do assistente e pararam porque o container temporário estava em uso.
  Elas não chegaram à etapa de conexão. A mensagem genérica foi substituída por
  motivo explícito e um lock impede testes simultâneos neste checkout. O teste
  do lock confirmou saída 75 e nenhuma alteração da VPN. Não apagar um container
  ocupado nem executar testes de outros checkouts em paralelo: o peer reservado
  também é compartilhado no servidor.

## Ainda planejado

- Conferir uso de peers distintos no Mac e celular, sem compartilhar credenciais.
- Completar DNS e cobertura de reconexão/IPv6 em Wi-Fi e rede móvel. O bloqueio
  básico IPv6 do iPhone passou no cenário relatado; repetir em outra rede e
  registrar rede usada e estado da Retransmissão Privada para ampliar a cobertura.
- Medir MTU, latência, taxa e uso de CPU durante tráfego sustentado e Hermes ativo.
- Guardar cópia externa segura da identidade age; hoje ela está somente no Mac.
- Reboot completo anterior ao coletor aprovado. Falta novo ensaio de reboot
  com o coletor, recuperação de senha e restauração de desastre.
- Orçamento agregado da conta OCI e canal externo para avisos. Histórico,
  limite local de 8 TB e avisos locais já implementados; sem cron do Hermes.

## Relatórios locais e remotos

Relatórios JSON em `evidence/` não são versionados. Cópias sanitizadas da Oracle
em `evidence/oracle/`; o estado/segredos não foram copiados.

- Mac interno aprovado: `tunnel-20261116T032712Z.json`.
- Oracle interno aprovado: `tunnel-20261116T032711Z.json` e `tunnel-20261116T032923Z.json`.
- Mac → Oracle, falha externa com limpeza confirmada: `tunnel-20261116T033404Z.json`.
- Auditoria final Oracle: `runtime-20261116T033436Z.json`.
- Painel privado via SSH: `private-ui-ssh.json`.
- Endpoint público aprovado: `tunnel-20261116T200341Z.json` (15 verificações).
- Falha inicial sem handshake: `tunnel-20261116T195538Z.json`.
- Conflitos com teste em andamento: `tunnel-20261116T200240Z.json`,
  `tunnel-20261116T200250Z.json` e `tunnel-20261116T200331Z.json`.
- Administração com VPN: `admin-with-vpn.json`.
- Backup e restauração inicial: `backup-restore.json` (inclui rejeição de corrupção).
- Backup pós-ajustes: `backup-restore-20261116T203303Z.json`.
- Recuperação automática: `evidence/oracle/restart-20261116T203124Z.json`.
- Cliente após reinício: `native-after-restart.json`.
- DNS/IPv6 básico: `mac-dns-ipv6-basic.json`.
- Confirmação IPv6 do iPhone: `iphone-ipv6-user-validation.json` (relato do operador).

A auditoria intermediária `oracle-runtime-20261116T033217Z.json` antecede a
correção da limpeza e usa a presença de qualquer `INIT_*` como indicador amplo;
não representa o estado final nem prova presença de senha no container.

## Controle de tráfego implantado

8 TB decimais/mês compartilhados, UTC, avisos locais em 50%, 75% e 90%.
Histórico por dispositivo, saída VPN e saída da interface externa da VM são
medições separadas. Nenhum conteúdo de navegação é registrado.

Sete testes de ledger e ensaio de kernel isolado passaram: limite de 4096
bytes, interrupção real por SIGKILL, nenhuma reemissão de saldo incerto,
fechamento de resto menor que um pacote, mês novo e autorização expirada.
O bootstrap da VPN foi observado com passagem fechada e zero bytes aceitos
antes do controlador. Depois da ativação, passaram os 15 testes externos da
VPN e um download limitado de 2 MiB pelo perfil nativo do Mac, cujo estado
inicial foi restaurado. O reinício limpo do controlador preservou o banco
e manteve o container VPN. Containers Hermes permaneceram com IDs e horários
de início iguais aos anteriores, e o smoke de isolamento passou.

Amostra curta do coletor: 8,83 MiB de memória corrente, pico de 16,16 MiB e
0,57% de um núcleo em 10 s. Não é teste de throughput máximo ou streaming.
Banco cifrado no backup, restauração offline e invariantes de orçamento
conferidos; o banco vivo nunca foi substituído.

Evidências: `evidence/traffic-rollout/summary.json`,
`evidence/tunnel-20261118T005629Z.json` e
`evidence/backup-restore-20261118T010801Z.json`. Procedimento em
[TRAFEGO.md](TRAFEGO.md). Avisos externos e uso agregado da conta OCI não
foram configurados. Não há consumo anterior à implantação reconstruído.
