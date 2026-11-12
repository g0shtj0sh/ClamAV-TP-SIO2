# TP — Antivirus ClamAV sur un poste Linux

Je documente dans ce dépôt un travail pratique réalisé sur le poste Debian de mon infrastructure **JCorp**. L'objectif est de déployer l'antivirus open source **ClamAV** sur un poste de travail Linux joint à un domaine Active Directory, puis de le piloter depuis une interface graphique, **ClamUI**, afin qu'il reste utilisable par une personne qui ne travaille pas en ligne de commande.

Ce dépôt est volontairement séparé de celui de l'infrastructure : [**JCorp-SISR**](https://github.com/g0shtj0sh/JCorp-SISR) décrit le socle (réseau, Active Directory, postes, NAS) et les deux ateliers professionnels, tandis que le présent dépôt ne contient que ce TP et ses preuves.

| Document | Contenu | État |
| --- | --- | --- |
| [Rapport du TP](Rapport-TP-ClamAV.md) | Déroulé complet, commandes, résultats observés et captures | **Terminé** |
| [Guide des captures](images/README.md) | Nomenclature des images | **Complet**, 44 captures |

## Contexte

Le TP s'appuie sur une machine déjà en service dans mon infrastructure, et non sur une machine créée pour l'occasion.

| Élément | Valeur |
| --- | --- |
| Machine | VM **702**, `User2-JCorp-Debian`, sur le nœud Proxmox `pve` |
| Système | Debian 13.3, bureau GNOME (session Wayland) |
| Rôle | Poste de travail utilisateur |
| Adressage | `10.2.101.11/24`, passerelle `10.2.101.1` |
| Réseau | VLAN **700**, pont Proxmox `vmbr2` |
| Domaine | `ad.jcorp`, poste joint dans l'OU `Postes`, authentification par SSSD |
| DNS | `10.2.101.10` (`JCORP-DC01`), suffixe de recherche `ad.jcorp` |
| Compte de test | `jfernandes@ad.jcorp`, dossier personnel `/home/jfernandes@ad.jcorp` |

Les prérequis de ce TP — jonction au domaine, résolution DNS interne et externe, synchronisation de l'horloge — ont été validés lors de la mise en place du socle et sont documentés dans [la documentation des postes utilisateurs](https://github.com/g0shtj0sh/JCorp-SISR/blob/main/Infrastructure/Postes%20utilisateurs/Postes-utilisateurs.md) du dépôt d'infrastructure. Je les contrôle néanmoins à nouveau au début du TP, car un dépôt APT inaccessible ferait échouer à la fois l'installation et la mise à jour des signatures.

## Objectifs

1. Installer le moteur ClamAV et télécharger ses bases de signatures.
2. Mettre le démon `clamav-daemon` en service et contrôler son état.
3. Vérifier la chaîne de détection avec le fichier de test EICAR.
4. Activer la protection en temps réel `clamonacc` sur un répertoire ciblé, avec mise en quarantaine.
5. Planifier une analyse récurrente à l'aide d'un service et d'un *timer* systemd.
6. Installer ClamUI et piloter l'ensemble depuis son tableau de bord.
7. Établir une recette : contrôle par contrôle, résultat attendu et preuve associée.

## Périmètre

Ce TP porte sur **un seul poste**. Le déploiement de ClamAV sur l'ensemble du parc, la centralisation des alertes antivirus dans la supervision Grafana/Prometheus et l'intégration à GLPI ne font pas partie de ce travail : ces briques sont planifiées dans l'atelier professionnel 1 du dépôt d'infrastructure et ne sont pas encore installées.

ClamAV est ici utilisé comme **une** brique de sécurité, pas comme une protection suffisante à elle seule. Ses limites sont discutées à la fin du rapport.

## Avancement

- [x] Étape 1 — Installation du moteur et des signatures *(12 novembre 2026, ClamAV 1.4.3, 108 Mio de signatures)*
- [x] Étape 2 — Démon `clamav-daemon` *(actif, 947 Mio en mémoire, socket locale sans exposition réseau)*
- [x] Étape 3 — Test de détection EICAR *(détecté, supprimé et journalisé ; écart de 400 pour 1 entre `clamscan` et `clamdscan`)*
- [x] Étape 4 — Protection en temps réel et quarantaine *(détection sans commande, déplacement automatique vers `/var/quarantine`)*
- [x] Étape 5 — Analyse planifiée *(timer hebdomadaire actif, couvre tout `/home` sans limite de taille)*
- [x] Étape 6 — Interface graphique ClamUI *(ClamUI 0.6.0, détection validée ; deux écarts avec la ligne de commande documentés)*
- [x] Étape 7 — Recette et conclusion *(19 contrôles conformes sur 20, l'écart restant étant démontré et expliqué)*

Aucune case n'est cochée avant que le contrôle correspondant ait été exécuté et sa preuve enregistrée.

**TP terminé le 12 novembre 2026.** Les quatre mécanismes de protection sont en service sur la VM 702 : analyse à la demande, protection en temps réel, analyse hebdomadaire planifiée et interface graphique. Les limites rencontrées et les prolongements envisagés sont traités au chapitre 9 du rapport.

## Sources

- [Guide ClamAV : installer et configurer un antivirus sur un serveur Linux](https://www.it-connect.fr/guide-clamav-installer-et-configurer-un-antivirus-sur-linux/) — IT-Connect
- [ClamUI : un antivirus graphique pour votre PC Linux](https://www.it-connect.fr/tuto-clamui-linux-interface-graphique-clamav/) — IT-Connect
- [Documentation officielle ClamAV](https://docs.clamav.net/Introduction.html)
- [Dépôt du projet ClamUI](https://github.com/linx-systems/clamui)
