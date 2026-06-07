# Portfolio Cybersécurité — Dimitri

Technicien issu d'un environnement technique exigeant en reconversion active vers la cybersécurité.  
Formation intensive autodidacte de 22 semaines (mars–août 2026) orientée pratique : chaque compétence est documentée par un lab réel et un write-up structuré.  
Disponible en Hauts-de-France — ouvert aux opportunités en **technicien sécurité IT**, **administrateur systèmes & réseaux junior** et  **analyste SOC N1**.

---

## Compétences démontrées en lab

| Domaine | Ce qui a été fait |
|---|---|
| SIEM / Splunk | Investigation complète sur dataset BOTS v1 : SPL (rex, timechart, dedup), corrélation multi-sources, attribution APT, analyse ransomware Cerber |
| Sécurité réseau | Déploiement pfSense CE architecture trois zones WAN/LAN/DMZ, NAT Port Forwarding, filtrage stateful, hardening WebGUI |
| Analyse réseau | Analyse de captures pcap, extraction de credentials, reconstruction de kill chain, enrichissement VirusTotal |
| Sécurité applicative | SQLi UNION-based et Blind Boolean sur DVWA, brute force Hydra, command injection, reverse shell en environnement contrôlé |
| Systèmes | Installation et administration de base Kali Linux, Debian 13, Windows CLI — lab multi-VM sous VirtualBox |
| GRC | RGPD, ISO 27001, NIS2, guides ANSSI — notions théoriques |
| Certifications | CompTIA Security+ SY0-701 — prévu juillet 2026 |

---

## Write-ups et exercices pratiques

Structure de chaque write-up : contexte métier → méthodologie → résultats → analyse → recommandations actionnables.

| Lab | Date |
|---|---|
| [pfSense N2 — Architecture trois zones NordLogistique (reconstruction from scratch)](semaine_12/write_up_pfsense_segmentation_reseau.md) | juin 2026 |
| [Déploiement pfSense et politique de filtrage réseau](semaine_11/Introduction_pfSense.md) | juin 2026 |
| [DVWA - Brute Force et Command Injection](semaine_10/write_up_DVWA_Decouverte.md) | mai 2026 |
| [Investigation SOC BOTSv1 - Ransomware Cerber](semaine_10/write_up_SOC_Investigation_Cerber.md) | mai 2026 |
| [Investigation réseau PacketMaze - Wireshark](semaine_10/write_up_wireshark_packetmaze.md) | mai 2026 |
| [Investigation SOC BOTSv1 - APT Po1s0n1vy](semaine_09/write_up_SOC_investigation.md) | mai 2026 |
| [Cross-Site Scripting (XSS)](semaine_09/write_up_XSS.md) | mai 2026 |
| [Injection SQL](semaine_09/write_up_injection_SQL.md) | mai 2026 |
| [Investigation Web - Wireshark](semaine_09/write_up_wireshark_investigation_web.md) | mai 2026 |
| [Lab Splunk — Analyse de logs Windows](semaine_08/write_up_splunk.md) | avril 2026 |
| [Scan Nmap — Vulnérabilités](semaine_07/write_up_nmap_vuln.md) | avril 2026 |
| [Scan Nmap — Metasploitable 2](semaine_06/write_up_nmap_metasploitable.md) | avril 2026 |

---

## Environnement de lab

- **Hyperviseur :** VirtualBox sur Windows (Ryzen 5 5600X, 32 Go RAM)
- **VMs actives :** Kali Linux · Debian 13 · pfSense CE · Metasploitable 2
- **Architecture courante :** réseau trois zones WAN/LAN/DMZ avec pfSense en coupure
- **SIEM local :** Splunk Free (ingestion de logs réels)
- **Outils utilisés :** Nmap · Wireshark · Splunk/SPL · Hydra · Netcat · DVWA

---

## Contact

Hauts-de-France — Disponible pour opportunités en cybersécurité (CDI, CDD, alternance)
