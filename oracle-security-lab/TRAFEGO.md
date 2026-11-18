# Histórico e cota da VPN pessoal

Política aprovada pelo titular: **8 TB/mês compartilhados entre Mac e iPhone**,
avisos em 50%, 75% e 90%. Configuração em `config/traffic-policy.json`.
TB é decimal nesta política: `8 000 000 000 000 bytes`; GiB/MiB são identificados
explicitamente nos relatórios. O período é o mês civil em UTC.

## Consultar pelo Mac

```sh
cd /Users/guga/workspace/my-vpn/oracle-security-lab
python3 scripts/traffic-status.py
python3 scripts/traffic-status.py --json
```

O helper usa SSH pela interface física, inclusive com a VPN ativa. Exibe modo,
estado do serviço, consumo, orçamento comprometido, reserva incerta e consumo
por dispositivo. O JSON também contém totais diários do mês, eventos e a última
atualização do controlador. Registros por dispositivo têm resolução de um minuto;
o status do controlador é atualizado aproximadamente a cada dez segundos.

Na VM:

```sh
sudo python3 /opt/hermes-security-vpn/scripts/traffic-meter.py status
sudo journalctl -u hermes-vpn-traffic.service -n 40 --no-pager
```

Avisos de 50%, 75% e 90% correspondem a 4, 6 e 7,2 TB de orçamento comprometido.
São persistidos no banco e emitidos no journal, uma vez por marco/mês. Desde
18/11 também são enviados ao chat privado do Hermes pelo serviço separado
hermes-vpn-notify.service, com outbox/recibos e retries; detalhes ao final.

## O que é contado

Há três medições distintas, que não devem ser somadas entre si:

1. **Dispositivos:** `wg show wg0 transfer`, identificando somente peers
   cadastrados no wg-easy. RX do servidor corresponde principalmente a upload;
   TX corresponde principalmente a download. A chave pública é convertida em
   um identificador hash; não é armazenada em claro no histórico de tráfego.
2. **Cota VPN:** saída atribuível à VPN. Contamos uploads encaminhados de `wg0`
   para a Internet e UDP criptografado emitido pelo servidor na porta 51820,
   incluindo downloads e handshakes. Não contamos novamente o download interno
   antes de encapsulá-lo. Peers temporários de teste também consomem essa cota.
3. **VM:** bytes TX da interface física de saída, sem somar bridges/veths.
   Inclui outros serviços, SSH e backups. Não cobre outras VMs da conta.

O kernel usa uma tabela nftables própria, `inet hermes_vpn_traffic`, no namespace
da VPN. Hooks de forward/output em prioridade -10 coexistem com os bloqueios
privados/DNS existentes. Não altera INPUT do host, Hermes, OCI ou outros projetos.
Pacotes contados podem sofrer bloqueio/retransmissão em outros pontos; essas
medições não reproduzem exatamente a cobrança. O uso informado pela OCI continua
a referência financeira. Os 10 TB divulgados pela Oracle não são exclusivos
desta VPN, e 8 TB de cota local não garantem custo zero para toda a conta.

O histórico começou com a implantação. **Não reconstrói tráfego anterior**,
inclusive a parte anterior do primeiro mês. A previsão mensal só aparece após
uma hora de coleta e extrapola a taxa observada desde o início do período
monitorado; não é uma previsão de faturamento.

## Persistência, privacidade e retenção

O banco fica em `/opt/hermes-security-vpn/state/traffic/traffic.db`, diretório
0700 e arquivo 0600, acessível pelo operador root. Usa SQLite/WAL com gravações
FULL. O controlador é um serviço systemd do host, independente do Hermes;
nenhum socket Docker, banco ou histórico é montado na LLM.

São armazenados horário UTC, identificador local/alias do dispositivo,
diferenças de bytes, geração dos contadores, totais diários, reservas e eventos.
Não há captura de pacotes, URLs, consultas DNS, IPs de sites, vídeos ou conteúdo.
O coletor lê somente nome e chave pública do cadastro de clientes do wg-easy,
sem copiar chaves privadas, tokens ou endpoints para o histórico.

Detalhes de um minuto: sete dias. Totais diários/eventos/reservas encerradas:
aproximadamente doze meses. A expiração remove apenas linhas deste banco novo;
não apaga arquivos, resultados, sessões ou workspaces de outros projetos.
Totais mensais de controle são preservados. São bases diferentes do Hermes.

Boot/container/interface novos e contadores que diminuem são registrados como
descontinuidades. O trecho entre a última amostra e uma falha pode faltar no
detalhe por dispositivo. Isso não devolve automaticamente orçamento da cota.

## Por que uma reserva não é consumo real

Antes de autorizar tráfego, o controlador compromete em transação durável uma
parcela de até **256 MiB**. Só depois instala a autorização correspondente no
kernel. O kernel impede exceder essa parcela mesmo se o processo controlador
parar; a renovação não depende da LLM ou de uma leitura por minuto.
Cada autorização também vence no kernel no final do mês UTC, impedindo que
um controlador morto prolongue a reserva de um mês para o seguinte.

Na renovação normal, fecha o encaminhamento, lê o contador estável, registra o
uso e devolve o saldo comprovadamente não utilizado. Só então reserva a próxima
parcela e troca a tabela em uma transação nftables. A quota é global para os
dois sentidos de saída VPN, não uma autorização separada por dispositivo.

Se houver morte abrupta ou troca incerta de namespace, a reserva pendente é
contabilizada integralmente. Uma falha pode portanto comprometer até 256 MiB
sem corresponder a esse volume real. O relatório distingue consumo medido,
orçamento com reserva e saldo incerto. Evita-se devolver crédito que possa ter
sido utilizado. Uma autorização antiga nunca é repetida a partir do banco.
Quando os últimos bytes do mês não comportam mais um pacote, esse pequeno
saldo também é encerrado conservadoramente, evitando reemissões sem utilidade.

Na subida do container, `VPN_TRAFFIC_ENFORCE=1` instala uma passagem fechada
antes de criar o WireGuard. O serviço só abre após verificar o ledger e gravar
uma reserva. Banco ausente/truncado não é reinicializado automaticamente.
Em caso de SIGKILL, uma autorização já emitida pode continuar até consumir a
parcela previamente reservada; isso é limitado e já está comprometido no mês.

Ao esgotar a cota, o tráfego VPN fica bloqueado. SSH administrativo pela interface
física e interfaces privadas de gestão continuam disponíveis. Não desligamos
o cliente nem mudamos suas rotas para uma conexão comum. O comportamento dos
aplicativos/rotas fora do túnel depende do cliente; não é um kill switch global
do sistema operacional. No mês seguinte, o serviço concede a nova cota e
preserva o histórico anterior; relógio voltando a mês anterior recusa autorização.

## Operação e recuperação

Unidade: `hermes-vpn-traffic.service`, habilitada para boot, dependente de Docker,
com reinício em falha. Limites próprios: 128 MiB, 64 tarefas e 10% de uma CPU.
O WireGuard mantém seus limites anteriores e o Hermes não recebe novas permissões.

Em uma instalação nova, após criar/configurar o wg-easy e os dispositivos,
inicializar uma única vez e instalar a unidade:

```sh
cd /opt/hermes-security-vpn
sudo python3 scripts/traffic-meter.py init
sudo install -m 0644 systemd/hermes-vpn-traffic.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hermes-vpn-traffic.service
```

Não repetir `init` em uma instalação existente; o comando recusa sobrescrever
o diretório. Recuperação de estado existente exige preservação/reconciliação.

```sh
sudo systemctl status hermes-vpn-traffic.service --no-pager
sudo systemctl restart hermes-vpn-traffic.service
```

Uma parada normal fecha a passagem e contabiliza a autorização antes de sair.
Com o serviço parado, a VPN não deve continuar encaminhando tráfego. Reiniciar
o serviço preserva o banco; não executar `init` novamente, apagar o banco ou
restaurar uma cópia antiga para liberar franquia.

O Compose base já contém `VPN_TRAFFIC_ENFORCE=1`. O override explícito é mantido:

```sh
cd /opt/hermes-security-vpn
docker compose -f compose.yaml -f compose.traffic.yaml up --pull never -d vpn
```

Em manutenção manual, parar primeiro o coletor, depois a VPN; ao subir a VPN,
iniciar/reiniciar também o coletor. O limite de tentativas do systemd pode
deixá-lo parado após ausência prolongada do container.

Não remove/reinicializa o estado. Se a passagem permanecer fechada, investigar
o serviço e o ledger pelo SSH, sem desativar silenciosamente a proteção.

## Backup e limites de recuperação

`scripts/backup.py` agora inclui snapshot consistente do ledger, política e
fontes de recuperação no arquivo cifrado da VPN. O teste offline confere hashes,
integridade SQLite e igualdade entre orçamento comprometido, uso finalizado,
reservas ativas e reservas incertas. Não inicia o controlador restaurado nem
sobrescreve o banco vivo.

**Uma cópia antiga do ledger não pode ser colocada em produção sem reconciliar
o consumo posterior ao backup.** Caso contrário, o orçamento já gasto poderia
voltar a aparecer como disponível. A restauração de teste não faz essa troca.
Backups também retêm metadados antigos até que uma política de rotação seja
definida; a expiração do histórico vivo não remove versões antigas dos backups.

## Validações

- Diferenças de contadores, base inicial, mudança de geração e deduplicação de avisos.
- Reserva/refund normal, limite restante, recusa de reserva duplicada e relógio regressivo.
- Processo realmente morto por SIGKILL, persistência SQLite e reserva incerta sem crédito duplicado.
- Kernel em namespace sem rede externa: corte em 4096 bytes, nenhuma passagem além
  da cota, morte do controlador com autorização ativa e virada de mês simulada.
- Observação real com download de 2 MiB pelo perfil nativo do Mac e restauração
  do estado inicial do cliente.
- Passagem fechada e zero bytes aceitos após recriar o container, antes de iniciar o controlador.
- Após ativar 8 TB, teste externo completo da VPN: handshake, saída Oracle,
  DNS, destinos privados protegidos, revogação e remoção do peer temporário.

As fronteiras de mês e a cota pequena foram simuladas em estado isolado, sem
alterar o relógio da VM ou consumir a franquia de produção artificialmente.
Amostra curta do coletor em repouso: aproximadamente 8,83 MiB de memória
corrente e 0,57% de um núcleo em 10 s; não representa capacidade máxima.
Evidências consolidadas em `evidence/traffic-rollout/summary.json`.

Em 18/11 passaram restart isolado do Docker e novo reboot com o controlador e
notificador atuais. Conjunto pronto em 58,76 s e 110,80 s, respectivamente,
sem recuperação manual. Ledger consistente, orçamento sem rollback, identidade
e peers preservados, nenhum reenvio de trabalho de IA. Após cada um passaram
15 verificações externas do túnel; peers temporários removidos.

## Canal Telegram ativo (18/11/2026)

`traffic-notify.py` e `hermes-vpn-notify.service` estão ativos e habilitados para
boot, no chat privado vinculado ao HermesNeo10Bot. O notificador não faz polling.
O coletor de cota não recebe token e não precisa ser reiniciado para habilitar
o notificador. Este lê eventos de 50/75/90% e esgotamento, sem escrever no ledger,
e mantém outbox/recibos SQLite separados em state/traffic/notifications.db.

Retries e deduplicação persistentes passaram em teste offline, sem mensagens
externas ou consumo artificial de franquia. Um envio ambíguo após aceitação no
Telegram pode duplicar; os avisos incluem período/tipo como identificador.
Indisponibilidade do bot não altera o corte da cota. O backup passa a incluir
snapshot consistente dos recibos. Uma mensagem marcada TESTE foi enfileirada
pelo operador (`sudo python3 scripts/traffic-notify.py --queue-test`), aceita pela
API e teve recibo persistido em uma tentativa. O consumo/limite do ledger não
foi modificado. Não foi necessário reiniciar VPN ou coletor. A aceitação da API
não comprova visualização no dispositivo.

O notificador depende da ponte Telegram do Hermes estar disponível; ao parar
essa ponte ou usar modo CLI, avisos permanecem pendentes e tentam novamente.
Os avisos locais e a cota no kernel continuam independentes. O status distingue
serviço de notificação, pendentes e entregues; notification_channels do coletor
original descreve seus canais locais, enquanto Telegram pertence ao novo serviço.

Backups diários cifrados agora são coordenados pelo serviço de operações do
Hermes às 07h UTC/04h de Brasília, com cópia pelo Mac a cada seis horas quando
conectado. O primeiro par foi copiado e restaurado offline. Rotação no servidor
apenas para pares registrados por essa rotina, acima de 30 dias, com recibos de
cópia/restauração correspondentes, preservando sete pares recentes e sete
recentes verificados. Manuais, não verificados e cópias do Mac são preservados.
O notificador possui PartOf=docker.service para retomar com o Docker.
