#!/usr/bin/env python3
"""Mac: read-only VPN accounting report through the physical-interface SSH helper."""
import argparse
import datetime as dt
import json
from pathlib import Path
import subprocess

root=Path(__file__).resolve().parent.parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--json',action='store_true')
a=p.parse_args()
r=subprocess.run(['python3',str(root/'scripts/admin-ssh.py'),'--batch','--',
                  'sudo -n python3 /opt/hermes-security-vpn/scripts/traffic-meter.py status'],capture_output=True,text=True,timeout=35)
if r.returncode:raise SystemExit('Accounting status unavailable; inspect the dedicated host service privately.')
d=json.loads(r.stdout)
if a.json:
    print(json.dumps(d,indent=2));raise SystemExit(0)
c=d.get('controller',{});policy=d['policy']
print('VPN — '+d['period_utc']+' (UTC)')
print('Serviço: '+d['service_state']+' | modo: '+policy['mode']+' | passagem: '+c.get('gate','unknown'))
print('Saída medida: %.6f TB' % (c.get('measured_egress_including_live_bytes',d['finalized_egress_bytes'])/10**12))
print('Orçamento comprometido, incluindo reserva: %.6f / %.1f TB' % (d['charged_including_reservations_bytes']/10**12,policy['monthly_limit_bytes']/10**12))
print('Reserva conservadora após falhas/fechamento da cota: %.2f MiB' % (d['uncertain_reservations_bytes']/1048576))
print('Saída da VM desde o início da coleta: %.2f MiB (medição separada)' % (d['host_external_tx_bytes']/1048576))
for peer in d['peers']:
    label=''.join(x for x in peer['device'] if x.isprintable())
    print('%s: upload %.2f MiB | download %.2f MiB' % (label,peer['upload_bytes']/1048576,peer['download_bytes']/1048576))
print('Última atualização: '+c.get('last_update_utc','unknown'))
if d['service_state']!='active':print('ATENÇÃO: coletor não está ativo; autorização anterior é limitada ao saldo já reservado.')
for event in d['events']:
    if event['kind'].startswith('threshold_') or event['kind']=='quota_exhausted':print('AVISO: '+event['kind']+' em '+event['timestamp'])
n=d.get('notifications',{})
print('Telegram: '+n.get('service_state','not-installed')+' | pendentes: '+str(n.get('pending',0))+' | entregues: '+str(n.get('delivered',0)))
print('Avisos locais permanecem disponíveis. Dados anteriores à coleta não foram reconstruídos.')
