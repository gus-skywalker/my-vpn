# VPN pessoal no laboratório Oracle

**Controle de tráfego ativo:** 8 TB/mês compartilhados, mês civil UTC, avisos
locais em 50%, 75% e 90%, histórico persistente e corte no kernel. Consulta
`python3 scripts/traffic-status.py`. Arquitetura, limites e recuperação em
[TRAFEGO.md](TRAFEGO.md). O container começa com passagem fechada e depende
de `hermes-vpn-traffic.service` para autorizar bytes.

Piloto novo para Mac e celular. Implementação separada do Hermes, no mesmo host
`132.145.178.32` / `security-lab-vnic`, Ubuntu ARM64, Ashburn AD-2.
O servidor já está instalado. Em 16/11 às 17:03 BRT, o teste externo desde o
Docker do Mac passou nas 15 verificações após o ajuste de entrada informado
pelo operador. Ainda em 16/11, o operador confirmou funcionamento no Mac e no
celular. No Mac, apresentou IP de saída `132.145.178.32` no terminal e navegador.
Administração com a VPN ligada, backup cifrado/restauração isolada e recuperação
automática de queda do processo foram validados em 16/11. O bloqueio IPv6 foi
verificado no Mac e confirmado pelo operador no teste comparativo do iPhone.
Um reteste explícito no Wi-Fi também confirmou IPv4 funcionando e IPv6 sem resposta.
Reboot real e retomada automática passaram em 17/11. DNS, cobertura em outras
redes, desempenho sustentado e restart isolado do Docker ainda têm pendências.
Não repetir o bootstrap no estado existente. Executar somente um teste por vez;
o script agora recusa concorrência com uma mensagem explícita.
Não executar o bootstrap Ansible do diretório pai: suas regras globais e mudanças
de SSH não são apropriadas ao host compartilhado. O CoBudget não é destino de implantação.

## Arquitetura

```
Mac / celular -- WireGuard UDP 51820 --> VPN -- NAT --> internet (Oracle EUA)
Operador -- interface física / SSH 22 --> painel 127.0.0.1:51821
Hermes -- política/proxy próprios --> provedores já autorizados
```

- wg-easy 15.5.0, imagem ARM64 fixada por digest em `config/image-lock.json`.
- Rede Docker `172.30.87.0/24`; peers WireGuard `10.66.77.0/24`.
- Estado em volume Docker exclusivo `hermes-security-vpn_wireguard`, sob o
  armazenamento atual do Docker. Nenhum block volume Oracle adicional criado.
- `/tmp` e `/run` em RAM, logs rotacionados, raiz somente leitura. Estado contém
  chaves privadas e banco do painel: não publicar, versionar ou compartilhar.
- Limites iniciais: 0,25 CPU, 512 MiB, 128 processos. Não constituem garantia de
  velocidade; a CPU é compartilhada com Hermes (limite 0,85 CPU em host de 1 CPU).
- Apenas `NET_ADMIN`, sem socket Docker, `SYS_MODULE`, `/lib/modules`, rede host,
  credenciais cloud, diretórios SSH ou montagens do Hermes.
- Atualização manual, sem Watchtower, Authelia, Bunkerweb ou DNS em container.

## Isolamento aplicado

`scripts/vpn-entry.sh` instala regras nftables no namespace do próprio container,
antes do processo wg-easy. O hook raw/PREROUTING de `wg0` cobre pacotes decapsulados
antes das regras de encaminhamento/NAT do aplicativo. Bloqueia redes privadas,
loopback, link-local/metadados, faixas especiais, peers entre si, o IP público da
própria VM e o IP público informado do CoBudget (`150.136.11.57`).
O painel não fica acessível por dentro do túnel VPN.
No Mac, `scripts/admin-ssh.py` vincula somente a conexão SSH à interface física
`en0`, usando o `nc` nativo. Isso mantém a administração acessível com a VPN
ligada, sem mudar rotas globais ou permitir acesso dos peers ao host. Se mudar
para outra interface física, ajustar `config/admin-mac.json` ou usar `--interface`.

DNS TCP/UDP porta 53 somente para `1.1.1.1` e `1.0.0.1`. Navegação HTTPS pode usar
DoH: essa regra não força todo software a usar um resolvedor específico.
IPv6 do servidor desativado; perfis incluem `::/0` para capturá-lo no túnel,
sem encaminhamento IPv6 no servidor. A ausência de vazamento exige teste nos
clientes reais. Desligar o túnel pode restaurar a conexão normal: não foi
implementado um kill switch dos dispositivos. Rotas locais mais específicas
também dependem da configuração do cliente.

O aplicativo precisa de `NET_ADMIN` para gerir WireGuard. As regras isolam o
tráfego dos peers; não são uma defesa independente contra comprometimento do
próprio processo administrativo. Hermes não recebe essa capacidade nem acesso
às chaves da VPN. Nenhuma regra global de SSH/firewall é substituída; o Docker
gerencia somente as redes/NAT do projeto novo.

## Preparação e bootstrap privado

Verificar primeiro identidade, kernel WireGuard, CIDRs, portas livres e espaço.
Compose precisa suportar `!override`, `interface_name` e `gw_priority` (testado
com 2.39.1 na Oracle). Não reutilizar estado ou peers da instalação antiga.

```sh
cd /opt/hermes-security-vpn
python3 scripts/prepare.py --endpoint-ip 132.145.178.32
docker compose -f compose.yaml -f compose.bootstrap.yaml -f compose.test.yaml up -d
python3 scripts/wait-ready.py
# Retira INIT_PASSWORD e demais variáveis de bootstrap do container em execução.
docker compose -f compose.yaml -f compose.private.yaml -f compose.test.yaml up -d
python3 scripts/wait-ready.py
python3 scripts/test-tunnel.py
```

`prepare.py` cria senha aleatória em `state/bootstrap.env` (0600), sem exibi-la.
Não executar `docker compose config` com o overlay de bootstrap, nem compartilhar
`docker inspect` completo: podem conter a senha. A preparação recusa sobrescrita.
Não copiar o estado do Mac para a Oracle. O teste usa cliente descartável sem
internet direta, chaves em tmpfs e peer temporário removido ao final.

No terminal do Mac, deixar o túnel SSH aberto (funciona com a VPN ligada):

```sh
cd /Users/guga/workspace/my-vpn/oracle-security-lab
python3 scripts/admin-ssh.py --dashboard
```

Abrir `http://127.0.0.1:51821` no Mac. Em outro terminal interativo:

```sh
python3 /Users/guga/workspace/my-vpn/oracle-security-lab/scripts/admin-ssh.py --password
```

Esse comando revela a senha **somente ao operador**. Não enviar a saída ao chat.
Usuário `vpnadmin`. Criar dois peers distintos no painel (`mac-guga` e
`celular-guga`). Importar perfis localmente; QR code e `.conf` são credenciais.

## Publicação posterior ao teste privado

No Console OCI, verificar a VNIC desta VM e seus NSGs/security lists efetivos.
Permitir entrada **UDP destino 51820**, origem compatível com os clientes
(celular pode precisar `0.0.0.0/0`). WireGuard autentica peers por chave.
Não abrir TCP 51821, nem outras portas para o painel. Não alterar SSH 22.
Não presumir que a regra foi criada ou que o IP público é estático.

Depois dos testes privados e da regra OCI:

```sh
cd /opt/hermes-security-vpn
# Base publica UDP, preservando a UI em loopback; remove a rede de teste.
docker compose -f compose.yaml up -d
python3 scripts/wait-ready.py
```

Nesta arquitetura o NAT faz o tráfego sair com o endereço da VNIC. Não desligar
source/destination check por rotina; não há roteamento VCN entre redes privadas.
O serviço usa `restart: unless-stopped`. A queda do processo foi testada e o
Docker recuperou a VPN em 11,57 s, preservando os dois peers e a identidade.
O reboot completo da VM passou em 17/11, com retomada automática da VPN e
do Hermes, preservação de peers e testes externos aprovados. O restart isolado
do daemon Docker ainda não foi ensaiado.
Uma parada manual permanece respeitada. A política não reinicia containers
apenas por estarem unhealthy, nem atualiza a imagem automaticamente.

## Backup e recuperação

Backup cifrado com age v1.3.2, chave privada somente no Mac e destinatário público
na Oracle. Os binários ficam na área `state/tools`, com digest fixado e conferido;
não são instalados globalmente. Cópias cifradas no Mac e na VM. Restauração
testada em container sem rede/portas, com volume descartável, sem tocar no estado
em produção. Procedimentos e custódia da chave em `OPERACAO.md`.

Para gerar outra cópia e verificar sua restauração, no Mac:

```sh
cd /Users/guga/workspace/my-vpn/oracle-security-lab
python3 scripts/backup.py
```

Ainda é necessário guardar uma cópia da identidade de recuperação fora deste
Mac, em local privado e seguro. Backups continuam manuais; o coletor de
tráfego agora é periódico, fora do Hermes.

## Aceite e operação

Confirmar, separadamente no Mac e celular (Wi-Fi e rede móvel): IP de saída
`132.145.178.32`, navegação, DNS/IPv6, desconexão/reconexão, MTU, taxa sustentada,
latência e revogação. Não prometer acesso a streaming ou geolocalização por país:
serviços podem identificar e bloquear IPs de datacenter.

O teste automatizado verifica handshake, DNS e HTTPS pelo túnel, contadores de
DROP para os destinos bloqueados, revogação e recursos de cgroup. Não substitui
testes externos nem mede a capacidade de streaming. Evidências em `evidence/`.
Contadores do WireGuard reiniciam com recriações; para orçamento mensal, medir
tráfego OCI agregado da conta. O histórico local e a cota com reservas duráveis
agora estão ativos; detalhes em [TRAFEGO.md](TRAFEGO.md).

Em 18/11 passaram restart isolado do Docker e novo reboot com o controlador e
notificador atuais, seguidos de 15 verificações externas cada. Avisos Telegram,
backup diário cifrado e cópia/restauração pelo Mac estão ativos; ver TRAFEGO.md.
Permanecem cópia externa das identidades de recuperação, testes de DNS/IPv6 em
mais cenários dos clientes e observação do orçamento agregado da conta OCI.
Não criar automações de limpeza ou atualizações sem uma política definida.
Nunca executar `docker system prune --volumes` ou remover o volume para atualizar.

Retorno sem afetar Hermes:

```sh
docker compose -f compose.yaml -f compose.private.yaml -f compose.test.yaml down
```

O comando preserva o volume; não usar `-v`. Remover apenas a regra UDP adicionada
para a VPN no OCI, se houver. Não restaurar um dump global antigo de iptables.

## Referências oficiais

- [Release 15.5.0](https://github.com/wg-easy/wg-easy/releases/tag/v15.5.0)
- [Código e configuração da versão fixada](https://github.com/wg-easy/wg-easy/tree/v15.5.0)
- [Opções do wg-easy](https://wg-easy.github.io/wg-easy/v15.3/advanced/config/optional-config/)
- [Regras de segurança OCI](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securityrules.htm)

Documentação publicada pode apontar versão diferente: variáveis e comportamento
foram conferidos também no código da tag fixada. Ver `VALIDACAO.md` para o estado
efetivamente executado, separado dos próximos passos.
