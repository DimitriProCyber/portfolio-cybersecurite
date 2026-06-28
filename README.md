# Portfolio Cybersécurité — Dimitri

Technicien issu d'un environnement technique exigeant en reconversion active vers la cybersécurité.  
Formation intensive autodidacte de 22 semaines (mars–août 2026) orientée pratique : chaque compétence est documentée par un lab réel et un write-up structuré.  
Disponible en Hauts-de-France — ouvert aux opportunités en **technicien sécurité IT**, **administrateur systèmes & réseaux junior** et  **analyste SOC N1**.

---

## Compétences démontrées en lab

| Domaine | Réalisations |
|---|---|
| Systèmes & Active Directory | Déploiement Windows Server 2022 : promotion DC, DNS/DHCP intégrés, structure OU, groupes de sécurité, GPO, audit et délégation de droits — domaine `dpro.lab` <br>Déploiement N2 niveau PME : 50 comptes utilisateurs via scripting PowerShell, GPO conformes ANSSI (politique de mot de passe, audit complet, restrictions), délégation de droits helpdesk, export de comptes inactifs, intégration de poste au domaine via GUI et PowerShell |
| Sécurité réseau | Déploiement pfSense CE en architecture trois zones WAN/LAN/DMZ, NAT Port Forwarding, filtrage stateful, hardening WebGUI |
| SIEM / Splunk | Investigation complète sur dataset BOTS v1 : SPL (rex, timechart, dedup), corrélation multi-sources, attribution APT, analyse ransomware Cerber |
| Analyse réseau | Analyse de captures pcap, extraction de credentials, reconstruction de kill chain, enrichissement VirusTotal |
| Sécurité applicative | SQLi UNION-based et Blind Boolean sur DVWA, brute force Hydra, command injection, reverse shell en environnement contrôlé |
| Environnement lab | Lab multi-VM sous VirtualBox : Kali Linux, Debian, Windows Server 2022, Windows 11, administration courante Linux et Windows CLI |
| GRC | RGPD, ISO 27001, NIS2, guides ANSSI — notions théoriques |
| Certifications | CompTIA Security+ SY0-701 — prévu juillet 2026 |

---

## Write-ups et exercices pratiques

Structure de chaque write-up : contexte métier → méthodologie → résultats → analyse → recommandations actionnables.

| Lab | Date |
|---|---|
| [Déploiement d'une infrastructure réseau PME complète](semaine_15/write_up_deploiement_infrastructure_reseau.md) | 27 juin 2026 |
| [Active Directory niveau 2 : déploiement d'un environnement PME](semaine_14/write_up_AD_deploiement_suite.md) | 14 juin 2026 |
| [Déploiement Active Directory : infrastucture d'annuaire pour une PME](semaine_13/write_up_AD_deploiement.md) | 11 juin 2026|
| [Déploiement et sécurisation d'une infrastructure réseau en trois zones avec pfSense)](semaine_12/write_up_pfsense_segmentation_reseau.md) | 06 juin 2026 |
| [Déploiement pfSense et politique de filtrage réseau](semaine_11/Introduction_pfSense.md) | 03 juin 2026 |
| [DVWA - Brute Force et Command Injection](semaine_10/write_up_DVWA_Decouverte.md) | 29 mai 2026 |
| [Investigation SOC BOTSv1 - Ransomware Cerber](semaine_10/write_up_SOC_Investigation_Cerber.md) | 25 mai 2026 |
| [Investigation réseau PacketMaze - Wireshark](semaine_10/write_up_wireshark_packetmaze.md) | 16 mai 2026 |
| [Investigation SOC BOTSv1 - APT Po1s0n1vy](semaine_09/write_up_SOC_investigation.md) | 13 mai 2026 |
| [Cross-Site Scripting (XSS)](semaine_09/write_up_XSS.md) | 09 mai 2026 |
| [Injection SQL](semaine_09/write_up_injection_SQL.md) | 08 mai 2026 |
| [Investigation Web - Wireshark](semaine_09/write_up_wireshark_investigation_web.md) | 03 mai 2026 |
| [Lab Splunk — Analyse de logs Windows](semaine_08/write_up_splunk.md) | 23 avril 2026 |
| [Scan Nmap — Vulnérabilités](semaine_07/write_up_nmap_vuln.md) | 19 avril 2026 |
| [Scan Nmap — Metasploitable 2](semaine_06/write_up_nmap_metasploitable.md) | 12 avril 2026 |

---

## Environnement de lab

- **Hyperviseur :** VirtualBox sur Windows (Ryzen 5 5600X, 32 Go RAM)
- **VMs actives :** Kali Linux · Debian 13 · pfSense CE · Metasploitable 2 · Windows Server 2022 (DC01) · Windows 11 Professionnel (PC01)
- **Architecture courante :** réseau trois zones WAN/LAN/DMZ avec pfSense en coupure · domaine Active Directory `dpro.lab`
- **SIEM local :** Splunk Free (ingestion de logs réels)
- **Outils utilisés :** Nmap · Wireshark · Splunk/SPL · Hydra · Netcat · DVWA · PowerShell AD

---

## Contact

Hauts-de-France — Disponible pour opportunités en cybersécurité (CDI, CDD, alternance)
