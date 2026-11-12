# Guide des captures

Les captures de ce TP sont déposées dans ce dossier et appelées depuis [le rapport](../Rapport-TP-ClamAV.md).

## Règles retenues

- Format **PNG** pour les captures d'écran, **JPG** accepté si la capture vient d'un appareil photo ou de la console Proxmox.
- Nom en minuscules, mots séparés par des tirets, préfixé par l'étape concernée.
- Une capture doit montrer la commande **et** sa sortie, pour que la preuve soit vérifiable.
- Aucun mot de passe visible à l'écran. Les invites de saisie sont acceptées, pas les mots de passe en clair.

## Captures attendues

| Fichier | Contenu attendu | État |
| --- | --- | --- |
| `etape1-etat-initial.png` | `apt update`, puis `hostnamectl`, `free -h` et `df -h /` sur la VM 702 | **Produite** |
| `etape1-prerequis-dns.png` | Résolution interne et externe, état de l'horloge | **Produite** |
| `etape1-installation-paquets.png` | Installation APT des six paquets | **Produite** |
| `etape1-version-moteur.png` | `clamscan --version` et liste des paquets installés | **Produite** |
| `etape1-freshclam-controles.png` | Mise à jour des bases, activation du service et contrôles de fin d'étape | **Produite** |
| `etape2-memoire-vm.png` | Mémoire de la VM 702 dans Proxmox, onglet Matériel | À produire |
| `etape2-memoire-avant.png` | `free -h` avant activation du démon | **Produite** |
| `etape2-daemon-status.png` | `systemctl status clamav-daemon` | **Produite** |
| `etape2-processus-memoire.png` | Processus ClamAV et `free -h` après activation | **Produite** |
| `etape2-socket-locale.png` | Directives de `clamd.conf` et `clamdscan --version` | **Produite** |
| `etape3-creation-fichiers.png` | Création du faux virus et du fichier témoin | **Produite** |
| `etape3-scan-eicar.png` | Détection du fichier de test par `clamscan` | **Produite** |
| `etape3-comparaison-scan.png` | Temps mesurés pour `clamscan` et `clamdscan` | **Produite** |
| `etape3-suppression-journal.png` | Suppression du fichier détecté et journal du démon | **Produite** |
| `etape4-prerequis.png` | Vérification de `clamonacc` et listage des dossiers personnels | **Produite** |
| `etape4-quarantaine.png` | Création du dossier de quarantaine et ses permissions | **Produite** |
| `etape4-config-ajout.png` | Ajout des directives de temps réel dans `clamd.conf` | **Produite** |
| `etape4-config-verif.png` | Contrôle de la configuration, dont `OnAccessMaxFileSize` | **Produite** |
| `etape4-service-unite.png` | Création de l'unité `clamonacc.service` | **Produite** |
| `etape4-service-clamonacc.png` | `systemctl status clamonacc` | **Produite** |
| `etape4-detection-quarantaine.png` | Répertoire surveillé vidé et fichier en quarantaine | **Produite** |
| `etape4-journal-tempsreel.png` | Journal `clamonacc` au moment de la détection | **Produite** |
| `etape5-service.png` | Création de l'unité `scan-home-hebdo.service` | **Produite** |
| `etape5-timer.png` | Création de l'unité `scan-home-hebdo.timer` | **Produite** |
| `etape5-calendrier.png` | `systemd-analyze calendar`, date normalisée | **Produite** |
| `etape5-timer-actif.png` | `systemctl list-timers` avec la prochaine exécution | **Produite** |
| `etape5-fichier-test.png` | Création du fichier de test hors du répertoire surveillé | **Produite** |
| `etape5-resultat-scan.png` | Statut du service, journal dédié et quarantaine | **Produite** |
| `etape6-telechargement.png` | Récupération des deux paquets et du fichier d'empreintes | **Produite** |
| `etape6-verification-integrite.png` | Contrôle des empreintes SHA-256 | **Produite** |
| `etape6-installation.png` | Installation par APT des paquets locaux | **Produite** |
| `etape6-fichier-test.png` | Préparation du fichier de test hors temps réel | **Produite** |
| `etape6-clamui-composants.png` | Inventaire des composants ClamAV détectés | **Produite** |
| `etape6-clamui-base-virale.png` | État des signatures et mise à jour depuis l'interface | **Produite** |
| `etape6-clamui-journaux.png` | Historique des opérations | **Produite** |
| `etape6-clamui-quarantaine.png` | Quarantaine de l'interface, vide — écart documenté | **Produite** |
| `etape6-clamui-statistiques.png` | Système annoncé protégé après zéro fichier analysé | **Produite** |
| `etape6-clamui-audit.png` | Audit de sécurité du système | **Produite** |
| `etape6-clamui-reseau.png` | Connexions réseau, absence de port lié au démon | **Produite** |
| `etape6-clamui-analyse.png` | Analyse rapide sur un répertoire vide | **Produite** |
| `etape6-clamui-scan-detection.png` | Analyse de `~/Documents` avec détection effective | **Produite** |
| `etape6-clamui-resultats.png` | Détail de la menace et actions proposées | **Produite** |

Ce tableau est mis à jour au fur et à mesure : une ligne passe à « Produite » seulement quand le fichier est présent dans ce dossier.

[Retour au rapport](../Rapport-TP-ClamAV.md) · [Présentation du TP](../README.md)
