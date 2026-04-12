Scan Nmap — Metasploitable 2

12 avril 2026

Objectif : Découverte de Nmap et de sa logique de fonctionnement


Environnement :

 - Kali Linux : 192.168.56.100
 - Metasploitable 2 : 192.168.56.101
 - Réseau isolé VirtualBox (labnet)


Commandes utilisées :

 - nmap 192.168.56.101 : va scanner les 1000 ports les plus courants sur Metasploitable et afficher tous ceux qui sont ouverts.
 - nmap -sV 192.168.56.101 : -sV va permettre d'identifier le logiciel qui tourne sur chaque port ainsi que sa version.
 - nmap -sV -sC 192.168.56.101 -oN scan_metasploitable.txt :-sC va lancer des scripts de détection automatiques afin d'obtenir des informations supplémentaires 
							                                                                                                  sur chaque services. -oN permet de sauvegarder les résultats dans un fichier texte dans le répertoire 
			                                                                                                          où l'on se trouve au moment de lancer la commande.


Résultats clés :

 - Nombre de ports ouverts : 24
 - Résultat du port FTP (vsftpd 2.3.4) : version de vsftp qui contient une backdoor intégrée volontairement par un attaquant ayant compromis le code source. Elle permet
					                                                            en envoyant un smiley ":)" dans le nom d'utilisateur d'ouvrir un shell root sur la machine.
 - Résultat du port SSH (OpenSSH 4.7) : ancienne version avec de nombreuses vulnérabilités connues.


Conclusion :

Ce scan m'a permis de découvrir Nmap ainsi que de comprendre comment commencer à l'utiliser. J'ai pu comprendre qu'il était facile avec le bon outil d'obtenir des 
informations qui pouvaient permettre de compromettre une machine. Il apparait qu'il est important d'une part de contrôler le nombre de ports ouverts et de limiter
ce nombre à ceux strictement nécessaires. D'autre part, lorsqu'un port est ouvert, il est impératif de s'assurer que les logiciels qui fonctionnent dessus soient à jour 
afin de limiter au maximum les risques.
Dans notre exemple, un attaquant qui dispose de ses informations pourrait facilement exploiter la backdoor vsftpd pour obtenir un accès root complet à la machine 
sans authentification. 
