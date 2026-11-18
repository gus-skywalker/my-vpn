# Operação do piloto VPN — ajustes de 16/11/2026

## Administração com VPN ativa

O perfil WireGuard continua bloqueado para o host e redes internas. O Mac usa
um caminho administrativo separado: `nc -b en0` vincula somente o socket SSH à
interface Wi-Fi física, e o SSH mantém autenticação, criptografia e conferência
da chave de host. Nenhuma rota global, regra OCI ou firewall de peers foi aberta.

No Mac:

```sh
cd /Users/guga/workspace/my-vpn/oracle-security-lab
python3 scripts/admin-ssh.py
```

Painel (deixar o comando aberto; acessar `http://127.0.0.1:51821`):

```sh
python3 scripts/admin-ssh.py --dashboard
```

Se essa porta local estiver ocupada, usar `--local-port 51822` e abrir a porta
correspondente no navegador. Senha somente no terminal interativo do operador:

```sh
python3 scripts/admin-ssh.py --password
```

`en0` foi verificada neste Mac. Ethernet ou outra máquina podem exigir
`--interface en5` ou ajuste em `config/admin-mac.json`. Interfaces `utun` não são
aceitas para esse caminho. O comando SSH comum continua sujeito às rotas da VPN.

## Backup manual cifrado e verificação

No Mac, com ou sem a VPN ligada:

```sh
python3 scripts/backup.py
```

O comando pede à Oracle um snapshot SQLite consistente, cifra com a chave
pública age, copia o arquivo cifrado para o Mac e verifica a restauração em
container isolado na Oracle. Nenhum arquivo de backup em claro é gravado no Mac.
O snapshot claro usa `/dev/shm` na Oracle e é removido; o ensaio restaura em volume
descartável, também removido. O serviço em uso não é parado pelo backup.

Inclui banco do wg-easy, configuração WireGuard, credencial inicial de bootstrap
e fontes mínimas de recuperação. O banco é a fonte de configuração do aplicativo;
o wg-easy regenera a interface ao iniciar. Os arquivos de backup são credenciais
sensíveis, mesmo cifrados, e ficam fora do Git.

Locais:

- Chave privada age: `state/recovery/backup-identity.txt` no Mac, modo 0600.
- Destinatário público: `state/backup-recipient.txt` nos dois hosts.
- Backups: `backups/*.tar.gz.age` nos dois hosts, acesso restrito.
- Ferramentas age: `state/tools/{darwin-arm64,linux-arm64}`; versão/digests em
  `config/age-lock.json`, conferidos contra os assets oficiais.

Guardar uma cópia privada da identidade de recuperação em gerenciador de senhas
ou armazenamento offline seguro. Sem ela, os arquivos cifrados não poderão ser
recuperados. Não enviar essa identidade, perfis, QR codes ou senhas pelo chat.
A cópia externa da identidade ainda depende do operador; não foi feita por nós.

Para verificar uma cópia existente sem criar outra:

```sh
python3 scripts/backup.py --restore-only backups/ARQUIVO.tar.gz.age
```

O ensaio não restaura sobre produção: confere os hashes, a integridade SQLite,
a identidade WireGuard e a resposta do painel em uma cópia sem rede e sem
portas publicadas. Para recuperação real, preservar primeiro o volume atual e
escolher explicitamente qual backup restaurar. Não substituir o volume em uso
com os comandos do ensaio.

## Recuperação automática

`restart: unless-stopped` está no Compose e foi aplicado ao container existente.
Foi encerrado somente o processo Node da VPN. O Docker reiniciou o container
automaticamente em 11,57 s, com os dois peers e a identidade preservados. Os
containers Hermes e as regras INPUT do host permaneceram iguais.

Reboot completo da VM aprovado em 17/11, autorizado pelo operador: novo boot
observado por SSH em 45,94 s; Hermes e WireGuard prontos automaticamente em
62,64 s, sem início manual. Dois peers preservados, 15 verificações externas
aprovadas e perfil nativo existente do Mac com saída `132.145.178.32`. O iPhone
não foi retestado nesta rodada. Estado inicial do Mac restaurado para desconectado.
Restart isolado do daemon Docker ainda não foi testado. Parada manual é
respeitada; a política não corrige sozinha um serviço unhealthy ainda em execução.

O script `test-restart.py` provoca interrupção real e não é um monitor periódico.
Executar somente durante manutenção, após backup verificado. Não há cron novo.

## DNS e IPv6

Com a VPN do Mac ativa, o resolvedor principal mostrou 1.1.1.1/1.0.0.1. Há
resolvedores locais com escopo da interface física; essa inspeção não é captura
de pacotes e não comprova ausência de todo vazamento DNS ou DoH.

O teste direto a um IPv6 literal público não conectou pela rota normal, enquanto
o mesmo destino respondeu quando vinculado explicitamente à interface física.
Isso confirma bloqueio do caminho IPv6 padrão nessa conexão do Mac, sem depender
do retorno IPv4-mapped de `curl -6`. Não cobre outras redes nem o celular.

No iPhone, o operador confirmou a sequência: endpoint IPv6 acessível sem VPN,
inacessível com VPN, IPv4 funcionando durante a VPN e IPv6 acessível novamente
após desligar o túnel. O bloqueio passou nesse cenário relatado. A confirmação
não reexplicitou rede utilizada ou estado da Retransmissão Privada. Para ampliar
a cobertura, repetir em outra rede e registrar esses detalhes. Não confundir
esse resultado com teste de vazamento DNS ou auditoria de todos os aplicativos.

No reteste explicitamente em Wi-Fi, com novas URLs de verificação, o operador
confirmou IPv4 funcionando e ausência de resposta IPv6. A observação inicial de
IPv6 temporariamente visível não teve causa determinada; não se presume que
fosse cache nem se conclui cobertura das transições entre redes.

Próximas validações: DNS por tráfego real, outras redes Wi-Fi/móvel, MTU,
desempenho sustentado com Hermes ativo e restart isolado do daemon Docker.
Evidência do reboot: `evidence/reboot-20261117T235838Z.json`.

Referências: [age](https://github.com/FiloSottile/age/releases/tag/v1.3.2),
[políticas de reinício Docker](https://docs.docker.com/engine/containers/start-containers-automatically/).

## Histórico e cota mensal de tráfego

Implementados 8 TB/mês compartilhados entre Mac e iPhone, em UTC, com avisos
locais em 50%, 75% e 90%. O serviço `hermes-vpn-traffic.service` mantém histórico
fora do Hermes e reserva saldo durável antes de liberar parcelas no kernel.
O backup cifrado passou a incluir o ledger e sua restauração offline.

No Mac: `python3 scripts/traffic-status.py` ou `--json` para totais diários.
Na VM: `sudo python3 /opt/hermes-security-vpn/scripts/traffic-meter.py status`.

A reserva de até 256 MiB não é consumo real. Queda abrupta pode contabilizar
a parcela de forma conservadora. Detalhes, operação, canais de aviso ainda
locais e limites da restauração em [TRAFEGO.md](TRAFEGO.md). Não apagar/resetar
o banco para liberar cota. Um backup antigo exige reconciliar consumo posterior
antes de qualquer restauração em produção.
