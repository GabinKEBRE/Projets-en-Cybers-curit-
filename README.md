# LAB 02 — SIEM/XDR maison : Wazuh, télémétrie endpoint et alerting

> **En une phrase :** déploiement d'un SIEM open-source complet, raccordement d'endpoints Windows et Linux avec une télémétrie de qualité, écriture de règles de détection et alerting opérationnel.

| | |
|---|---|
| **Domaine** | SOC / Detection — **le domaine qui recrute le plus** |
| **Durée** | 14-18 h sur 5-6 sessions |
| **Plateformes** | Proxmox (profil P2) + VMware (profil V1) |
| **RAM mobilisée** | Proxmox : Wazuh 5 Go + pfSense 1 Go · VMware : Win11 3,5 Go |
| **Prérequis** | Lab 01 terminé (VLAN 20 opérationnel, remote syslog pfSense préparé) |

---

## PARTIE A — Prérequis et dimensionnement

### A.1 Le défi RAM et sa solution

Wazuh en configuration standard réclame 6-8 Go. Tu en as 5. **C'est faisable, mais il faut brider l'indexer OpenSearch**, qui est le composant gourmand. On vise :

| Composant | RAM standard | RAM bridée (ce lab) |
|---|---|---|
| Wazuh Indexer (OpenSearch) | 4 Go heap | **1,5 Go heap** |
| Wazuh Manager | 1-2 Go | 1 Go |
| Wazuh Dashboard | 1 Go | 0,7 Go |
| Système Debian | 0,5 Go | 0,5 Go |
| **Total VM** | ~8 Go | **~4,5 Go (alloue 5)** |

Cette contrainte est pédagogiquement utile : tu vas comprendre où passe la mémoire d'un SIEM, ce que peu de gens savent expliquer.

### A.2 Créer la VM Wazuh sur Proxmox

```bash
# Sur le Proxmox, VM Debian 12
qm create 110 --name HUB-SIEM-01 --memory 5120 --cores 3 --cpu host \
  --net0 virtio,bridge=vmbr1,tag=20 \
  --scsihw virtio-scsi-pci --scsi0 local-lvm:60 \
  --ide2 local:iso/debian-12-netinst.iso,media=cdrom \
  --boot order=ide2 --ostype l26 --onboot 0
qm start 110
```

**Points d'attention à la création :**
- `tag=20` place directement la carte dans le VLAN SERVERS — pas besoin de configurer le VLAN dans l'OS.
- 60 Go de disque : un SIEM grossit vite. En dessous de 40 Go, l'indexer se met en lecture seule dès que le disque atteint 85 %.
- 3 cœurs : l'indexation est gourmande en CPU au démarrage.

### A.3 Installation Debian et configuration réseau

Installation minimale (SSH + utilitaires standard). Puis :

```bash
cat > /etc/network/interfaces.d/siem <<'EOF'
auto ens18
iface ens18 inet static
    address 10.20.20.10/24
    gateway 10.20.20.1
    dns-nameservers 10.20.20.1 1.1.1.1
EOF
systemctl restart networking
ping -c2 10.20.20.1     # la passerelle SERVERS
ping -c2 1.1.1.1        # Internet (règle FW-002 du lab 01)
```

**Point de contrôle 1 :** la VM joint sa passerelle et Internet. Si Internet échoue → vérifie la règle `FW-002` (SERVERS → WAN) du lab 01.

### A.4 Prérequis système impératifs

```bash
# 1. max_map_count — SANS ça, l'indexer ne démarre jamais
echo "vm.max_map_count=262144" > /etc/sysctl.d/99-wazuh.conf
sysctl -p /etc/sysctl.d/99-wazuh.conf

# 2. Docker
apt update && apt install -y ca-certificates curl gnupg git
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
apt update && apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker
```

> **Piège classique n°1 :** oublier `vm.max_map_count`. Le symptôme est cryptique — l'indexer redémarre en boucle avec `max virtual memory areas vm.max_map_count [65530] is too low`. C'est l'erreur n°1 de tout déploiement Elastic/OpenSearch.

---

## PARTIE B — Déploiement de Wazuh

### B.1 Récupérer et brider

```bash
cd /opt
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker/single-node
```

**Brider l'indexer** — éditer `docker-compose.yml`, service `wazuh.indexer` :

```yaml
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1536m -Xmx1536m"   # au lieu de 4g
    mem_limit: 2g
```

Et pour le dashboard, ajouter `mem_limit: 800m`.

### B.2 Générer les certificats et changer les mots de passe

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

**Changer immédiatement les mots de passe par défaut.** Générer un hash :

```bash
docker run --rm -ti wazuh/wazuh-indexer:4.9.0 \
  bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p 'TonMotDePasseFort'
```

Reporter le hash dans `config/wazuh_indexer/internal_users.yml` (utilisateurs `admin` et `kibanaserver`), et le mot de passe en clair dans `docker-compose.yml` (`INDEXER_PASSWORD`, `DASHBOARD_PASSWORD`) et `config/wazuh_dashboard/wazuh.yml`.

> **Ne commite jamais ces fichiers en clair.** Ajoute-les à `.gitignore` et publie une version `.example` avec des placeholders.

### B.3 Démarrer

```bash
docker compose up -d
docker compose ps          # les 3 services doivent être "healthy" après ~3 min
docker compose logs -f wazuh.indexer   # surveiller le démarrage
```

**Point de contrôle 2 :** `https://10.20.20.10` (depuis une VM du VLAN MGMT ou via tunnel SSH) affiche la page de connexion Wazuh. Connexion avec ton nouveau mot de passe admin.

Si l'indexer ne démarre pas :
```bash
free -h                                    # reste-t-il de la RAM ?
docker compose logs wazuh.indexer | grep -i error
dmesg | grep -i "killed process"           # l'OOM killer a-t-il frappé ?
```

### B.4 Recevoir les logs de pfSense

Au lab 01, tu as pointé le syslog de pfSense vers `10.20.20.10:514`. Wazuh écoute déjà en 514/udp. Vérifie :

```bash
docker exec -it single-node-wazuh.manager-1 bash
tail -f /var/ossec/logs/archives/archives.log    # si activé
```

Active l'archivage de tous les événements (utile pour le lab 03) dans `config/wazuh_cluster/wazuh_manager.conf` :
```xml
<logall>yes</logall>
<logall_json>yes</logall_json>
```
Puis `docker compose restart wazuh.manager`.

**Point de contrôle 3 :** génère du trafic bloqué depuis REDLAB (lab 01) et retrouve-le dans Wazuh → **Threat Hunting**, filtre `location:*pfsense*` ou par IP source.

---

## PARTIE C — Raccorder les endpoints

### C.1 Agent Windows + télémétrie de qualité

Sur la VM Windows 11 (profil V1, segment CORP-PC du site VMware, `10.30.30.x`) :

**1. Installer l'agent Wazuh.** Depuis l'interface : **Agents → Deploy new agent** → Windows → serveur `10.20.20.10` → copier la commande PowerShell générée (elle contient la clé d'enrôlement) → l'exécuter en administrateur.

```powershell
# la commande ressemble à :
.\wazuh-agent-4.9.0.msi /q WAZUH_MANAGER="10.20.20.10" WAZUH_AGENT_NAME="PC-WKS-01"
NET START WazuhSvc
```

> **Piège classique n°2 :** l'agent Windows au site VMware doit atteindre `10.20.20.10` **à travers le tunnel WireGuard**. Vérifie d'abord `Test-NetConnection 10.20.20.10 -Port 1514`. Si ça échoue, le problème est dans le routage du lab 01, pas dans Wazuh.

**2. Installer Sysmon** — la télémétrie native de Windows est pauvre, Sysmon la transforme :

```powershell
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "C:\Sysmon" -Force
# configuration maintenue par la communauté (sysmon-modular d'Olaf Hartong)
Invoke-WebRequest "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -OutFile "C:\Sysmon\sysmonconfig.xml"
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```

**3. Faire remonter Sysmon dans Wazuh** — éditer `C:\Program Files (x86)\ossec-agent\ossec.conf`, ajouter avant `</ossec_config>` :

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[EventID=4624 or EventID=4625 or EventID=4672 or EventID=4720 or EventID=4728 or EventID=4732 or EventID=4688]</query>
</localfile>
```

```powershell
Restart-Service WazuhSvc
```

Chaque `EventID` filtré a un rôle : 4624/4625 authentifications réussies/échouées, 4672 privilèges spéciaux, 4720 création de compte, 4728/4732 ajout à un groupe, 4688 création de processus. **Sache expliquer chacun** (niveau N2).

**Point de contrôle 4 :** l'agent `PC-WKS-01` apparaît **Active** dans Wazuh, et **Threat Hunting** montre des événements `data.win.system.providerName: Microsoft-Windows-Sysmon`.

### C.2 Agent Linux + auditd

Sur la passerelle Debian du site VMware (ou une VM Ubuntu dédiée) :

```bash
# Installer l'agent
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.0-1_amd64.deb
WAZUH_MANAGER="10.20.20.10" WAZUH_AGENT_NAME="PC-GW-01" dpkg -i wazuh-agent_4.9.0-1_amd64.deb
systemctl enable --now wazuh-agent

# Renforcer auditd avec un ruleset de référence
apt install -y auditd
curl -sL https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules -o /etc/audit/rules.d/hardening.rules
augenrules --load
systemctl restart auditd
```

Faire lire le log auditd par l'agent — dans `/var/ossec/etc/ossec.conf` de l'agent :
```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```
```bash
systemctl restart wazuh-agent
```

### C.3 Activer les modules de sécurité

Dans la config du manager (ou par groupe d'agents via **Management → Groups**) :

- **FIM** (surveillance d'intégrité) sur `/etc`, `/bin`, `/sbin`, `C:\Windows\System32` — alerte à toute modification
- **Vulnerability Detection** — corrèle les paquets installés avec les CVE
- **SCA** (Security Configuration Assessment) — évalue la conformité CIS automatiquement
- **Rootcheck** — recherche de rootkits et anomalies

**Point de contrôle 5 :** l'onglet **Configuration Assessment** d'un agent affiche un score CIS. C'est ta première mesure de posture (elle servira au lab 07).

---

## PARTIE D — Écrire des règles de détection

Wazuh a des milliers de règles intégrées. La compétence recherchée, c'est d'écrire **les tiennes**, adaptées à ton contexte. Fichier : `/var/ossec/etc/rules/local_rules.xml`.

### D.1 Cinq règles à écrire et comprendre

```xml
<group name="local,lab,">

  <!-- 1. Création de compte local Windows -->
  <rule id="100200" level="10">
    <if_sid>60106</if_sid>
    <field name="win.system.eventID">^4720$</field>
    <description>Création d'un compte utilisateur local sur $(win.system.computer)</description>
    <mitre><id>T1136.001</id></mitre>
  </rule>

  <!-- 2. Ajout à un groupe sensible -->
  <rule id="100201" level="12">
    <if_sid>60106</if_sid>
    <field name="win.system.eventID">^4732$</field>
    <field name="win.eventdata.targetUserName">Administrators|Administrateurs</field>
    <description>Ajout au groupe Administrateurs local sur $(win.system.computer)</description>
    <mitre><id>T1098</id></mitre>
  </rule>

  <!-- 3. Brute force SSH (5 échecs en 2 min depuis une même source) -->
  <rule id="100202" level="10" frequency="5" timeframe="120">
    <if_matched_sid>5716</if_matched_sid>
    <same_source_ip />
    <description>Brute force SSH probable depuis $(srcip)</description>
    <mitre><id>T1110.001</id></mitre>
  </rule>

  <!-- 4. Modification d'un fichier système surveillé (FIM) -->
  <rule id="100203" level="12">
    <if_sid>550</if_sid>
    <field name="file">/etc/passwd|/etc/shadow|/etc/sudoers</field>
    <description>Modification d'un fichier d'authentification critique : $(file)</description>
    <mitre><id>T1098</id></mitre>
  </rule>

  <!-- 5. PowerShell encodé (indicateur d'obfuscation) -->
  <rule id="100204" level="12">
    <if_sid>92000,91802</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}</field>
    <description>Commande PowerShell encodée en base64 sur $(win.system.computer)</description>
    <mitre><id>T1059.001</id></mitre>
  </rule>

</group>
```

**Pour chaque règle, tu dois pouvoir expliquer (N2) :** ce que fait `if_sid` (chaîner sur une règle parente), pourquoi le `level` choisi, ce que déclenche `frequency`/`timeframe`, et à quelle technique ATT&CK elle correspond.

### D.2 Tester une règle sans attendre l'événement réel

L'outil `wazuh-logtest` rejoue un log brut contre le moteur de règles :

```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
# coller un log Sysmon ou un événement, observer quelle règle matche et à quel niveau
```

C'est **le** réflexe du detection engineer : tester la règle, pas espérer qu'elle marche.

```bash
docker compose restart wazuh.manager   # recharger après édition des règles
```

---

## PARTIE E — Alerting opérationnel

### E.1 Intégration Telegram (réutilise ton bot existant)

Créer `/var/ossec/integrations/custom-telegram` dans le conteneur manager :

```bash
docker exec -it single-node-wazuh.manager-1 bash
cat > /var/ossec/integrations/custom-telegram <<'EOF'
#!/usr/bin/env python3
import sys, json, requests
alert_file = sys.argv[1]
hook_url   = sys.argv[3]   # renseigné dans ossec.conf
with open(alert_file) as f:
    alert = json.load(f)
rule  = alert.get("rule", {})
level = rule.get("level", 0)
if level < 10:                # ne notifie que le sérieux
    sys.exit(0)
agent = alert.get("agent", {}).get("name", "?")
desc  = rule.get("description", "sans description")
mitre = ",".join(rule.get("mitre", {}).get("id", []))
text  = f"🚨 [N{level}] {agent}\n{desc}\nATT&CK: {mitre or 'n/a'}"
token, chat = hook_url.split("|")
requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
              json={"chat_id": chat, "text": text}, timeout=10)
EOF
chmod 750 /var/ossec/integrations/custom-telegram
chown root:wazuh /var/ossec/integrations/custom-telegram
```

Dans `ossec.conf` du manager :
```xml
<integration>
  <name>custom-telegram</name>
  <hook_url>TON_TOKEN_BOT|TON_CHAT_ID</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

> **Point d'attention :** le token et le chat ID sont des secrets. Ne les commite pas. Publie la version avec `<hook_url>REDACTED</hook_url>`.

**Point de contrôle 6 :** déclenche une règle de niveau ≥ 10 (crée un compte local Windows) → reçois la notification Telegram en quelques secondes.

### E.2 Trois tableaux de bord

Dans Wazuh → **Dashboard management → Create** :

1. **Couverture MITRE** — visualisation par `rule.mitre.id`, pour voir ce que tu détectes.
2. **Top alertes par agent** — histogramme `agent.name` filtré sur `rule.level >= 10`.
3. **Authentifications** — courbe temporelle réussies (4624) vs échouées (4625).

---

## PARTIE F — Scénarios de simulation

### Scénario 1 — Détecter une création de compte malveillante

**Contexte :** un attaquant crée un compte de persistance après compromission.

```powershell
# sur PC-WKS-01, en administrateur
net user backdoor P@ssw0rd123! /add
net localgroup Administrators backdoor /add
```

**Attendu :** règles 100200 puis 100201 déclenchées, notification Telegram, événement visible dans le dashboard MITRE (T1136, T1098). **Nettoyer ensuite :** `net user backdoor /delete`.

### Scénario 2 — Détecter un brute force SSH

**Contexte :** tentative d'accès par force brute sur un serveur Linux.

```bash
# depuis Kali (REDLAB), activer temporairement le flux vers PC-GW-01
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.30.30.1 -t 4 -f
```

**Attendu :** règle 100202 après 5 échecs, `srcip` correctement extrait, alerte de niveau 10.

### Scénario 3 — Détecter une modification de fichier système

```bash
# sur PC-GW-01
useradd -M -s /bin/false testfim    # modifie /etc/passwd
```

**Attendu :** FIM déclenche la règle 100203, avec le hash avant/après du fichier visible dans l'alerte.

### Scénario 4 — Le silence est une alerte

**Contexte :** un attaquant désactive l'agent pour ne plus être vu.

```powershell
Stop-Service WazuhSvc
```

**Attendu :** Wazuh génère une alerte « agent disconnected » (règle intégrée 505). **La déconnexion d'un agent est un événement de sécurité**, pas un incident technique. Sache l'expliquer — c'est une question d'entretien fréquente.

---

## PARTIE G — Épreuves de maîtrise (N3)

| # | Panne à provoquer | Symptôme | Compétence testée |
|---|---|---|---|
| **1** | Remplir le disque à 90 % (`fallocate -l 50G /tmp/fill`) | L'indexer passe en lecture seule, plus d'ingestion | Gestion du cycle de vie des index, watermark OpenSearch |
| **2** | Casser un guillemet dans `local_rules.xml` | Le manager refuse de démarrer | Validation de config (`wazuh-logtest`, logs manager) |
| **3** | Bloquer le port 1514 sur pfSense | Les agents passent en « disconnected » | Diagnostic de la chaîne agent→manager |
| **4** | Envoyer un log Sysmon volontairement malformé | Aucune règle ne matche | Compréhension du parsing et des décodeurs |
| **5** | Écrire une règle qui génère 1000 alertes/min | Le dashboard devient illisible | Notion de faux positif et de bruit (transition vers lab 03) |

**Diagnostic de référence à maîtriser :** « Wazuh ne remonte plus rien depuis ce matin. » Ta démarche, du bas vers le haut : l'agent tourne-t-il ? (`systemctl status wazuh-agent`) → atteint-il le manager ? (`nc -z 10.20.20.10 1514`) → le manager tourne-t-il ? (`docker compose ps`) → l'indexer accepte-t-il l'écriture ? (disque, `_cluster/health`) → le dashboard interroge-t-il le bon index ?

### Épreuve N4 — Adaptation

Ajoute une **détection de désactivation de Windows Defender** (Event ID 5001 ou modification de la clé de registre `DisableAntiSpyware`), mappée sur T1562.001, avec alerte de niveau 12. Aucune procédure fournie : c'est le test.

---

## PARTIE H — Conclusion et livrables

### H.1 Mesures à consigner

| Indicateur | Valeur |
|---|---|
| Agents raccordés | 2 (1 Windows + 1 Linux) |
| Sources de logs | Sysmon, Security, auditd, syslog pfSense |
| Règles personnalisées écrites | 5 minimum + 1 (N4) |
| Techniques ATT&CK couvertes | à lister |
| Délai de détection moyen (événement → alerte) | à mesurer, en secondes |
| RAM réellement consommée par la VM | `free -h` sous charge |
| Score CIS initial des endpoints (SCA) | baseline pour le lab 07 |

### H.2 Livrables portfolio

```
02-siem-wazuh/
├── README.md
├── journal.md
├── docs/
│   ├── architecture-siem.png              # Figure 1
│   └── figures/
│       ├── fig02-dashboard-mitre.png
│       ├── fig03-alerte-creation-compte.png
│       ├── fig04-notification-telegram.png
│       └── fig05-detection-agent-offline.png
├── configs/
│   ├── docker-compose.yml.example         # mots de passe en placeholder
│   ├── local_rules.xml
│   ├── ossec-agent-windows.conf
│   ├── ossec-agent-linux.conf
│   └── custom-telegram.py.example         # token en placeholder
└── scripts/
    └── generate-test-events.ps1           # rejoue les 4 scénarios
```

### H.3 Critères de clôture

- [ ] 6 points de contrôle validés, captures numérotées
- [ ] 5 règles écrites, testées à `wazuh-logtest`, chacune expliquée (N2)
- [ ] 4 scénarios joués, alertes capturées
- [ ] 5 épreuves N3 réussies sans documentation
- [ ] Épreuve N4 réalisée
- [ ] Alerting Telegram fonctionnel
- [ ] Tableau : événement → règle → technique ATT&CK → délai de détection
- [ ] README rédigé, configs anonymisées, Gitleaks au vert
- [ ] Tu sais répondre en entretien à : « comment dimensionner un SIEM ? », « qu'est-ce qu'un faux positif et comment le réduire ? », « pourquoi Sysmon plutôt que les logs Windows natifs ? »

### H.4 Limites à assumer

> Ce SIEM est mono-nœud sans haute disponibilité ni réplication d'index — une perte de la VM perd les données. La rétention n'est pas configurée pour la conformité (NIS2 impose souvent 12 mois). L'indexer est volontairement sous-dimensionné : en production il faudrait 3 nœuds et un heap de 50 % de la RAM disponible. Enfin, la couverture de détection n'est pas mesurée objectivement — c'est précisément l'objet du lab 03.

---

*Lab suivant : `LAB-03` — Detection engineering. On mesure ce que ce SIEM détecte vraiment, on comble les trous avec des règles Sigma, et on chiffre la progression.*
