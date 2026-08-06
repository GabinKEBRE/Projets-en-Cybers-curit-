# 🛡️ Hybrid SOC — De l'attaque à la détection

> **Conception, déploiement et validation d'un SOC hybride reliant un lab offensif local à une infrastructure de détection cloud, du scan Nmap à la règle de corrélation.**

![Azure](https://img.shields.io/badge/Microsoft_Azure-0078D4?logo=microsoftazure&logoColor=white)
![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-005792)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)
![Kali](https://img.shields.io/badge/Kali_Linux-557C94?logo=kalilinux&logoColor=white)
![WireGuard](https://img.shields.io/badge/WireGuard-88171A?logo=wireguard&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Status](https://img.shields.io/badge/statut-en_cours-yellow)

---

## 📌 En une phrase

J'ai construit de bout en bout une architecture de sécurité distribuée — un SIEM et un endpoint Windows sur **Microsoft Azure**, reliés par un **tunnel VPN chiffré** à une machine d'attaque **Kali Linux** locale — puis j'ai mené de vraies attaques pour **mesurer et améliorer la capacité de détection** via une démarche **Purple Team**.

La valeur de ce projet ne réside pas dans l'installation d'outils, mais dans l'**ingénierie de détection** : identifier les angles morts, écrire des règles de corrélation mappées sur **MITRE ATT&CK**, réduire les faux positifs, et prouver chaque amélioration.

---

## 🏗️ Architecture

```
   ┌─────────────────────┐         WireGuard          ┌──────────────────────────────┐
   │   LAB LOCAL (Kali)   │◄════════ tunnel  ═════════►│        AZURE (eastus)         │
   │   VMware Workstation │      chiffré site-cloud    │   VNet 10.10.0.0/16            │
   │   10.99.0.2          │                            │                               │
   │   Red Team / attaque │                            │   ┌─────────────────────────┐ │
   └─────────────────────┘                            │   │ vmdebian  10.10.1.10     │ │
                                                       │   │ SIEM Wazuh + hub VPN     │ │
                                                       │   └─────────────────────────┘ │
                                                       │   ┌─────────────────────────┐ │
                                                       │   │ windows11 10.10.1.20     │ │
                                                       │   │ Endpoint (Win Server)    │ │
                                                       │   └─────────────────────────┘ │
                                                       └──────────────────────────────┘
```

*(Le schéma détaillé est disponible dans `/docs/architecture.png`.)*

**Principes de conception :**
- **Infrastructure hybride** : ressources cloud managées + lab local maîtrisé, reliés par un VPN chiffré.
- **Segmentation** : la machine offensive est isolée et n'atteint le SIEM que par le tunnel.
- **Adressage fixe** : IP privées statiques (`10.10.1.10` / `10.10.1.20`) et IP publique statique pour un endpoint VPN stable.
- **Maîtrise des coûts** : déallocation systématique des VMs hors session, budget d'alerte, auto-shutdown.

---

## 🧰 Stack technique

### Déjà déployé

| Domaine | Technologies |
|---|---|
| **Cloud & Infrastructure** | Microsoft Azure (VNet, NSG, VM, IP statique), Azure CLI, VMware Workstation |
| **SIEM / Détection** | Wazuh 4.9 (Indexer OpenSearch, Manager, Dashboard), Sysmon, Docker Compose |
| **Réseau & Accès** | WireGuard (VPN site-à-cloud), hub-and-spoke, NAT / routage IP |
| **Offensif (Red Team)** | Kali Linux, Nmap, Hydra (brute force RDP/SMB) |
| **Detection Engineering** | Règles Wazuh personnalisées, corrélation, MITRE ATT&CK |
| **Systèmes** | Windows Server 2022, Debian 12, journaux de sécurité Windows |

### Feuille de route (intégration progressive)

| Domaine | Outil | Objectif dans le lab |
|---|---|---|
| 🔥 Durcissement | **nftables** | Pare-feu Linux + détection des blocages dans le SIEM |
| 🎣 Sensibilisation | **Gophish** | Simulation de campagne de phishing + détection endpoint |
| 🌐 Edge | **Traefik** | Reverse proxy HTTPS + logs d'accès centralisés |
| 🔐 Zero Trust | **Teleport** | Bastion d'accès SSH/RDP avec audit de session |
| 🗝️ Secrets | **Passbolt** | Coffre-fort d'équipe + audit des accès |
| 📋 GRC | **CISO Assistant** | Mapping du lab sur ISO 27001 / NIST CSF |

---

## 🎯 Scénarios de détection réalisés

Chaque attaque est lancée depuis Kali, détectée par Wazuh, et mappée sur MITRE ATT&CK.

| # | Attaque simulée | Technique ATT&CK | Détection Wazuh |
|---|---|---|---|
| 1 | Création de compte malveillant | T1098 | Event 4720 — alerte niveau 8 |
| 2 | Ajout à un groupe privilégié | T1098 / T1484 | Event 4732 — règle native + custom niveau 12 |
| 3 | Effacement du journal de sécurité | T1070.001 | Event 1102 — anti-forensic |
| 4 | Reconnaissance réseau (scan de ports) | T1046 | Détection de scan |
| 5 | Brute force RDP | T1110.001 | Events 4625 → **règle de corrélation personnalisée** |

**Exemple de règle de corrélation développée** (détection de motif, pas d'événement isolé) :

```xml
<rule id="100015" level="12" frequency="5" timeframe="120">
  <if_matched_sid>60122</if_matched_sid>
  <same_field>data.win.eventdata.ipAddress</same_field>
  <description>Brute force RDP : 5+ échecs en 120s depuis $(data.win.eventdata.ipAddress)</description>
  <mitre><id>T1110.001</id></mitre>
</rule>
```

---

## 📂 Structure du dépôt

```
hybrid-soc/
├── README.md                  # ce fichier
├── docs/
│   ├── architecture.png       # schéma d'architecture
│   ├── rapport.md             # rapport technique complet (à venir)
│   └── figures/               # captures numérotées des détections
├── azure/
│   ├── rebuild-azure-lab.ps1  # déploiement IaC de l'infra Azure
│   └── create-vms.ps1         # provisionnement des VMs
├── vpn/
│   └── setup-wireguard-hub.sh # configuration du tunnel site-à-cloud
├── wazuh/
│   ├── docker-compose.yml.example
│   └── rules/
│       └── local_rules.xml    # règles de détection personnalisées
└── attacks/
    └── scenarios.md           # scénarios offensifs reproductibles
```

> ⚠️ **Sécurité du dépôt** : aucun secret n'est versionné. Les fichiers de configuration sont publiés en version `.example` avec des valeurs remplacées par des placeholders. Le `.gitignore` couvre `*.key`, `*.env`, `*.conf.real`.

---

## 🔍 Compétences démontrées

- **Cloud Security** : déploiement Azure sécurisé (segmentation NSG, moindre privilège, maîtrise des coûts)
- **SIEM & Detection Engineering** : déploiement Wazuh, écriture de règles, corrélation, MITRE ATT&CK
- **Réseau** : VPN WireGuard, architecture hub-and-spoke, segmentation, NAT
- **Purple Team** : attaque (Kali) et défense (SIEM) dans une même boucle de validation
- **Infrastructure as Code** : provisionnement scripté et reproductible
- **Documentation** : approche rigoureuse, retour d'expérience sur les difficultés réelles

---

## 📖 Retour d'expérience

Ce projet a été mené comme une vraie mission, avec ses obstacles. La section « Difficultés rencontrées » du rapport documente honnêtement les problèmes résolus — car savoir diagnostiquer vaut autant que savoir déployer :

- Diagnostic d'une **mauvaise topologie réseau** Azure (VNets isolés révélés par des IP privées identiques)
- Contournement de **restrictions de SKU** et de contraintes d'images cloud
- Résolution d'un **problème d'authentification de service** subtil (caractères spéciaux mal interprétés par le shell lors de la génération de hash)
- Débogage de **règles de détection** (SID parent, validation XML, corrélation)

---

## 👤 Auteur

**Gabin KEBRE** —  Etudiant en Cybersécurité
🔗 [Portfolio](https://gabinkebre.info) · 💼 En recherche d'alternance cybersécurité (septembre 2026)

---

## 📄 Licence

Projet personnel à visée pédagogique. Tous les tests offensifs ont été réalisés exclusivement sur une infrastructure dont je suis propriétaire, dans un environnement isolé.
![Azure](https://img.shields.io/badge/Microsoft_Azure-0078D4?logo=microsoftazure&logoColor=white)
![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-blue)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)
![Kali](https://img.shields.io/badge/Kali_Linux-557C94?logo=kalilinux&logoColor=white)
![WireGuard](https://img.shields.io/badge/WireGuard-88171A?logo=wireguard&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
