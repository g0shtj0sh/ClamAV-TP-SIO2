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
| `clamav-fonctionnement.png` | Schéma des composants ClamAV | À produire |
| `etape1-etat-initial.png` | `hostnamectl`, `free -h` et `df -h /` sur la VM 702 | À produire |
| `etape1-prerequis-dns.png` | Résolution interne et externe, état de l'horloge | À produire |
| `etape1-installation-paquets.png` | Installation APT et version du moteur | À produire |
| `etape1-freshclam.png` | Téléchargement des bases, versions et nombre de signatures | À produire |
| `etape1-controles.png` | Contenu de `/var/lib/clamav/` et état du service de mise à jour | À produire |
| `etape2-memoire-vm.png` | Mémoire de la VM 702 dans Proxmox | À produire |
| `etape2-daemon-status.png` | `systemctl status clamav-daemon` | À produire |
| `etape3-scan-eicar.png` | Détection du fichier de test par `clamscan` | À produire |
| `etape4-temps-reel.png` | Journal `clamonacc` au moment de la détection | À produire |
| `etape4-quarantaine.png` | Fichier déplacé dans le dossier de quarantaine | À produire |
| `etape5-timer.png` | `systemctl list-timers` avec la prochaine exécution | À produire |
| `etape6-clamui-accueil.png` | Tableau de bord ClamUI, état du moteur et des signatures | À produire |
| `etape6-clamui-scan.png` | Résultat d'une analyse lancée depuis ClamUI | À produire |
| `etape6-clamui-planification.png` | Écran de planification des analyses | À produire |

Ce tableau est mis à jour au fur et à mesure : une ligne passe à « Produite » seulement quand le fichier est présent dans ce dossier.

[Retour au rapport](../Rapport-TP-ClamAV.md) · [Présentation du TP](../README.md)
