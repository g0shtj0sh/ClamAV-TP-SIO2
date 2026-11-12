# Rapport de TP — Déploiement de ClamAV et de ClamUI sur un poste Debian

**Auteur :** Joshua Fernandes — SIO 2, option SISR
**Machine :** VM 702, `User2-JCorp-Debian`, Debian 13.3
**Date de réalisation :** à partir du 12 novembre 2026
**Dépôt d'infrastructure associé :** [JCorp-SISR](https://github.com/g0shtj0sh/JCorp-SISR)

---

## Sommaire

1. [Présentation de ClamAV](#1-présentation-de-clamav)
2. [Étape 1 — Installation du moteur et des signatures](#2-étape-1--installation-du-moteur-et-des-signatures)
3. [Étape 2 — Mise en service du démon](#3-étape-2--mise-en-service-du-démon)
4. [Étape 3 — Test de détection avec EICAR](#4-étape-3--test-de-détection-avec-eicar)
5. [Étape 4 — Protection en temps réel et quarantaine](#5-étape-4--protection-en-temps-réel-et-quarantaine)
6. [Étape 5 — Analyse planifiée](#6-étape-5--analyse-planifiée)
7. [Étape 6 — Interface graphique ClamUI](#7-étape-6--interface-graphique-clamui)
8. [Étape 7 — Recette](#8-étape-7--recette)
9. [Limites et conclusion](#9-limites-et-conclusion)

---

## 1. Présentation de ClamAV

ClamAV est un moteur antivirus open source principalement déployé sur les serveurs Linux et les NAS. Il ne cherche pas à deviner si un fichier est malveillant : il compare le contenu des fichiers à une **base de signatures virales**, c'est-à-dire un ensemble d'empreintes de logiciels malveillants connus, mise à jour régulièrement. Son efficacité dépend donc directement de la fraîcheur de cette base.

Il se décompose en plusieurs composants, qu'il faut distinguer pour comprendre la suite du rapport.

| Composant | Rôle |
| --- | --- |
| `clamscan` | Scanner autonome en ligne de commande, embarque son propre moteur |
| `clamd` (`clamav-daemon`) | Démon qui garde la base de signatures chargée en mémoire |
| `clamdscan` | Client léger qui interroge le démon `clamd` |
| `freshclam` | Service de mise à jour des bases de signatures |
| `clamonacc` | Analyse à l'accès (*On-Access*), c'est-à-dire en temps réel |

### Pourquoi deux outils de scan ?

`clamscan` et `clamdscan` font le même travail mais pas de la même façon, et le choix a des conséquences concrètes sur une machine aussi modeste que la VM 702.

| Critère | `clamscan` | `clamdscan` |
| --- | --- | --- |
| Démon requis | Non | Oui |
| Base de signatures | Rechargée à chaque exécution | Déjà chargée en permanence |
| Vitesse de démarrage | Lente, plusieurs secondes | Quasi instantanée |
| Mémoire | Plusieurs centaines de Mio à chaque lancement | Faible côté client, le démon porte la charge |
| Configuration | Options en ligne de commande | Hérite de `clamd.conf` |
| Accès aux fichiers | Lit directement les fichiers | Le démon tourne sous l'utilisateur `clamav`, d'où le besoin fréquent de `--fdpass` |

En clair : `clamscan` convient à une analyse ponctuelle ou planifiée la nuit, `clamdscan` convient à tout ce qui doit répondre vite, et la protection en temps réel impose le démon.

### Contrainte de dimensionnement relevée

Le démon `clamd` conserve l'intégralité de la base de signatures en mémoire, ce qui représente de l'ordre de **1 Gio de RAM**. La VM 702 avait été créée avec **2 Gio**, ce qui suffit à un poste bureautique sous GNOME mais laisse peu de marge une fois le démon chargé. La mémoire de la machine a donc été portée à **4,8 Gio** avant le début du TP, ce que confirme le relevé de l'état initial à l'étape 1. Cette décision est détaillée à l'étape 2.

---

## 2. Étape 1 — Installation du moteur et des signatures

### 2.1 Objectif

Installer le moteur ClamAV sur le poste et télécharger une base de signatures à jour, puis s'assurer que la mise à jour automatique est active.

### 2.2 État initial de la machine

Je relève l'état de départ avant toute modification, de façon à pouvoir justifier ensuite mes choix de dimensionnement.

```bash
sudo apt update
hostnamectl ; echo "---" ; free -h ; echo "---" ; df -h /
```

Les trois dépôts `trixie`, `trixie-security` et `trixie-updates` répondent. APT signale **70 paquets pouvant être mis à jour** : ces mises à jour ne sont pas appliquées dans le cadre de ce TP, afin de ne pas mélanger leurs effets avec ceux de l'installation de l'antivirus.

**Résultat observé :**

| Élément | Valeur relevée |
| --- | --- |
| Nom de machine | `User2-JCorp` |
| Système | Debian GNU/Linux 13 (trixie) |
| Noyau | `6.12.111+deb13-amd64`, architecture x86-64 |
| Virtualisation | KVM, machine `i440FX`, fournisseur QEMU |
| Mémoire totale | 4,8 Gio, dont **3,8 Gio disponibles** |
| Espace d'échange | 1,7 Gio, inutilisé |
| Disque racine | `/dev/sda1`, 30 Gio, 6,0 Gio utilisés, **23 Gio disponibles** (22 %) |

Ces deux derniers chiffres sont ceux qui comptent pour la suite : les bases de signatures occupent une centaine de mébioctets sur le disque, et le démon en chargera l'équivalent en mémoire. Avec 3,8 Gio de RAM disponible et 23 Gio d'espace libre, la machine est correctement dimensionnée pour accueillir ClamAV avec sa protection en temps réel.

![État initial de la VM 702](images/etape1-etat-initial.png)

### 2.3 Contrôle des prérequis réseau

Les bases de signatures pèsent une centaine de mébioctets et sont téléchargées depuis Internet. Un dépôt APT ou un serveur de mise à jour inaccessible ferait échouer les deux étapes suivantes, c'est pourquoi je contrôle la résolution de noms interne et externe ainsi que l'horloge avant de commencer.

```bash
getent hosts jcorp-dc01.ad.jcorp
getent ahostsv4 deb.debian.org
timedatectl
```

**Résultat attendu :** le contrôleur de domaine et un nom externe sont tous deux résolus, l'horloge indique `System clock synchronized: yes` et `NTP service: active`.

**Résultat observé :**

| Contrôle | Valeur relevée |
| --- | --- |
| Résolution interne | `jcorp-dc01.ad.jcorp` → `10.2.101.10` |
| Résolution externe | `deb.debian.org` → `199.232.82.132` (`debian.map.fastlydns.net`) |
| Horloge | `System clock synchronized: yes`, `NTP service: active` |

Les trois contrôles sont conformes. La résolution externe confirme que la correction des redirecteurs DNS sur `JCORP-DC01`, réalisée lors de la mise en place du socle, reste effective : le poste n'interroge que le DNS du domaine, et c'est le contrôleur qui relaie les demandes Internet.

![Contrôle du DNS et de l'horloge](images/etape1-prerequis-dns.png)

### 2.4 Installation des paquets

```bash
sudo apt update
sudo apt install -y clamav clamav-daemon
```

Ces deux paquets installent le moteur de détection ainsi que le démon, et entraînent l'installation des dépendances `clamav-base`, `clamav-freshclam`, `clamdscan` et `libclamav12`. Le service de mise à jour `freshclam` est donc présent sans avoir à l'installer explicitement.

**Résultat observé :** six paquets installés, **15,3 Mo téléchargés** et **70,5 Mo d'espace disque occupés**. APT crée à cette occasion deux liens symboliques qui préparent le démarrage automatique du démon :

```
/etc/systemd/system/multi-user.target.wants/clamav-daemon.service
/etc/systemd/system/sockets.target.wants/clamav-daemon.socket
```

La sortie contient la ligne `id: 'clamav' : utilisateur inexistant` pendant le paramétrage de `clamav-base`. Ce message n'est pas une erreur : il apparaît parce que le script de configuration vérifie l'existence du compte de service **avant** de le créer. L'installation se poursuit normalement et le compte `clamav` est bien présent ensuite, comme le confirme le propriétaire des fichiers de signatures au contrôle 2.6.

![Installation des paquets ClamAV](images/etape1-installation-paquets.png)

Je relève ensuite la version exacte du moteur, qui sera reportée dans la recette :

```bash
clamscan --version ; dpkg -l | grep clamav
```

**Résultat observé :** `ClamAV 1.4.3/28181/Thu Nov 12 07:27:14 2026`.

Cette chaîne se lit en trois parties : la version du **moteur** (1.4.3), la version de la **base quotidienne** (28181) et sa **date de compilation**. Les cinq paquets `clamav`, `clamav-base`, `clamav-daemon`, `clamav-freshclam` et `libclamav12` sont tous en version `1.4.3+dfsg-1` et à l'état `ii`, c'est-à-dire correctement installés et configurés.

![Version du moteur et paquets installés](images/etape1-version-moteur.png)

### 2.5 Téléchargement initial des signatures

Après l'installation, la base de signatures est vide : le moteur est en place mais il n'a encore rien à comparer. Une première mise à jour manuelle est donc nécessaire.

Le service `clamav-freshclam` démarre automatiquement à l'installation et maintient un verrou sur le répertoire des bases. Lancer `freshclam` à la main sans l'avoir arrêté provoque une erreur de verrou, d'où l'arrêt préalable du service.

```bash
sudo systemctl stop clamav-freshclam
sudo freshclam
```

Le service est ensuite remis en route et activé au démarrage, de façon à ce que la base reste à jour sans intervention :

```bash
sudo systemctl enable --now clamav-freshclam
```

**Résultat observé :** les trois bases sont annoncées `up-to-date`.

| Base | Version | Signatures |
| --- | --- | --- |
| `daily.cvd` | 28181 | 355 854 |
| `main.cvd` | 63 | 3 287 027 |
| `bytecode.cvd` | 339 | 80 |

Soit environ **3,64 millions de signatures** chargées.

#### Observation : les bases étaient déjà présentes

La commande `freshclam` n'a rien téléchargé, elle a constaté que les bases étaient à jour. L'explication se lit dans l'horodatage des fichiers : ils datent de **09 h 35**, c'est-à-dire du moment de l'installation, alors que ma commande manuelle a été lancée à **09 h 38**. Le service `clamav-freshclam` installé par APT a démarré tout seul et effectué le téléchargement initial avant que je l'arrête.

Ma commande manuelle n'a donc pas joué le rôle attendu de premier téléchargement, mais celui d'un **contrôle de fraîcheur**, ce qui reste une preuve valable pour la recette. L'étape conserve tout son sens : sur une machine où le service n'aurait pas pu sortir sur Internet, c'est bien cette commande qui aurait fait le travail et affiché l'erreur.

#### Observation : avertissement de version du moteur

La sortie contient un avertissement qu'il serait malhonnête de passer sous silence :

```
WARNING: Your ClamAV installation is OUTDATED!
WARNING: Local version: 1.4.3  Recommended version: 1.4.6
```

Le moteur installé depuis les dépôts Debian est en version 1.4.3, alors que le projet ClamAV publie la 1.4.6. Ce n'est **pas** un défaut de configuration de ma part, mais le fonctionnement normal d'une distribution stable : Debian fige la version d'un paquet pendant toute la durée de vie de la version stable et y rétroporte les correctifs de sécurité, plutôt que de suivre les versions amont.

Les conséquences concrètes sont les suivantes :

- **La détection n'est pas dégradée.** Ce qui détermine ce que l'antivirus reconnaît, ce sont les signatures, et elles sont à jour du jour même (base compilée le 12 novembre 2026 à 07 h 27).
- **Le moteur peut manquer des améliorations récentes**, notamment la prise en charge de nouveaux formats d'archives ou des corrections de performance.
- **Le compromis est acceptable** dans le contexte JCorp : la stabilité et l'application automatique des correctifs de sécurité Debian priment sur le fait de disposer de la toute dernière version amont. Installer le moteur depuis les sources imposerait de suivre ses mises à jour à la main sur chaque poste.

![Mise à jour des signatures et contrôles de fin d'étape](images/etape1-freshclam-controles.png)

### 2.6 Contrôles de fin d'étape

```bash
ls -alh /var/lib/clamav/ ; echo "---" ; systemctl is-enabled clamav-freshclam ; systemctl is-active clamav-freshclam
```

| Contrôle | Résultat attendu | Résultat observé | Conforme |
| --- | --- | --- | --- |
| Présence des bases | `main.cvd`, `daily.cvd` et `bytecode.cvd` présents, propriétaire `clamav` | `main.cvd` 85 Mio, `daily.cvd` 23 Mio, `bytecode.cvd` 276 Kio, plus `freshclam.dat` ; tous appartenant à `clamav:clamav` | Oui |
| Volume occupé | De l'ordre d'une centaine de mébioctets | **108 Mio** au total | Oui |
| Démarrage automatique | `enabled` | `enabled` | Oui |
| Service en fonctionnement | `active` | `active` | Oui |

À l'activation, systemd signale une synchronisation avec un script de démarrage SysV (`systemd-sysv-install`). C'est normal : le paquet Debian fournit encore un script d'init historique en parallèle de l'unité systemd, et l'activation met les deux mécanismes en cohérence.

Le volume relevé de 108 Mio correspond bien à l'ordre de grandeur annoncé, et reste négligeable au regard des 23 Gio disponibles sur la racine.

---

## 3. Étape 2 — Mise en service du démon

### 3.1 Objectif

Activer `clamav-daemon` et contrôler son état, après avoir traité la contrainte de mémoire identifiée au chapitre 1.

### 3.2 Décision de dimensionnement

La mémoire de la VM 702 a été portée de 2 Gio à **4,8 Gio** avant le TP, ce que confirme le relevé de l'état initial à l'étape 1 : 4,8 Gio au total, dont 3,8 Gio disponibles une fois le bureau GNOME chargé.

Ce choix est motivé par le fonctionnement du démon : `clamd` charge l'intégralité des bases de signatures en mémoire et les y maintient, soit environ 1 Gio en régime permanent. Avec les 2 Gio d'origine, le démon aurait consommé la moitié de la mémoire de la machine et aurait concurrencé le bureau graphique, avec un risque d'arrêt par le mécanisme de protection contre l'épuisement mémoire du noyau (*OOM killer*).

La protection en temps réel étant un objectif du TP et reposant sur le démon, ce dimensionnement est un prérequis et non un confort.

| Paramètre | Avant | Après |
| --- | --- | --- |
| Mémoire de la VM 702 | 2 Gio | 4,8 Gio |

_Capture de la configuration matérielle dans Proxmox à ajouter : `images/etape2-memoire-vm.png`._

La mesure réalisée en 3.5 confirme a posteriori que cette décision était nécessaire.

### 3.3 Relevé de la mémoire avant activation

Pour chiffrer le coût réel du démon plutôt que de reprendre un ordre de grandeur trouvé dans la documentation, je relève l'état de la mémoire avant de l'activer.

```bash
free -h
```

**Résultat observé :** 4,8 Gio au total, 1,1 Gio utilisés, **3,7 Gio disponibles**.

![Mémoire avant activation du démon](images/etape2-memoire-avant.png)

### 3.4 Activation et contrôle du service

```bash
sudo systemctl enable --now clamav-daemon
systemctl status clamav-daemon --no-pager
```

Comme pour `clamav-freshclam`, systemd synchronise l'unité avec le script de démarrage SysV encore fourni par le paquet Debian.

**Résultat observé :**

| Élément | Valeur relevée |
| --- | --- |
| État | `active (running)` depuis 09:55:48 |
| Démarrage automatique | `enabled` |
| Processus principal | PID 6348, `/usr/sbin/clamd --foreground=true` |
| Mémoire du service | **947,4 Mio** (pic identique) |
| Temps processeur consommé | 13,0 s |
| Déclenché par | `clamav-daemon.socket` |
| Fichier d'extension | `/etc/systemd/system/clamav-daemon.service.d/extend.conf` |

Deux éléments de cette sortie méritent une explication.

**L'activation par socket.** La ligne `TriggeredBy: clamav-daemon.socket` indique que le démon n'est pas simplement lancé au démarrage : systemd met en place la socket d'écoute et démarre `clamd` lorsqu'un client la sollicite. C'est le fonctionnement retenu par Debian, et il explique pourquoi le service peut apparaître à l'état `activating` pendant les premières dizaines de secondes : le temps processeur de 13 secondes relevé correspond au chargement des 3,64 millions de signatures en mémoire.

**Les étapes préalables.** Les deux lignes `ExecStartPre` créent le répertoire `/run/clamav` et en attribuent la propriété à l'utilisateur `clamav`. C'est ce répertoire qui accueillera la socket locale.

![Statut du démon clamav-daemon](images/etape2-daemon-status.png)

### 3.5 Processus et coût réel en mémoire

```bash
ps -edf | grep clam | grep -v grep
free -h
```

**Résultat observé :** deux processus, tous deux sous l'utilisateur non privilégié `clamav`.

| PID | Processus | Démarré à | Rôle |
| --- | --- | --- | --- |
| 5926 | `/usr/bin/freshclam -d --foreground=true` | 09:38 | Mise à jour des signatures en tâche de fond |
| 6348 | `/usr/sbin/clamd --foreground=true` | 09:55 | Moteur de détection résident |

Le fait que les deux tournent sous `clamav` et non sous `root` est un point de sécurité favorable : une faille dans le moteur d'analyse ne donnerait pas directement les privilèges administrateur sur le poste.

**Comparaison de la mémoire :**

| Moment | Utilisée | Disponible |
| --- | --- | --- |
| Avant activation | 1,1 Gio | 3,7 Gio |
| Après activation | 2,0 Gio | 2,8 Gio |
| **Écart** | **+0,9 Gio** | **−0,9 Gio** |

La mesure confirme l'ordre de grandeur annoncé au chapitre 1 et recoupe les 947,4 Mio rapportés par systemd. Elle valide surtout la décision de dimensionnement : sur la configuration d'origine à 2 Gio, le démon aurait occupé à lui seul près de la moitié de la mémoire de la machine, en concurrence directe avec le bureau GNOME. Dans la configuration retenue, il en consomme environ 20 % et laisse 2,8 Gio disponibles pour l'usage bureautique.

![Processus ClamAV et mémoire après activation](images/etape2-processus-memoire.png)

### 3.6 Mode de communication du démon

Le démon peut être joint de deux façons : par une **socket locale**, c'est-à-dire un fichier spécial accessible uniquement depuis la machine, ou par un **port TCP**, qui l'exposerait au réseau. La recommandation est d'utiliser la socket locale lorsque les clients se trouvent sur la même machine, ce qui est le cas ici.

```bash
grep -E '^(LocalSocket|TCPSocket|User|LogFile)' /etc/clamav/clamd.conf
clamdscan --version
```

**Résultat observé :**

| Directive | Valeur | Commentaire |
| --- | --- | --- |
| `LocalSocket` | `/var/run/clamav/clamd.ctl` | Communication par fichier de socket |
| `LocalSocketGroup` | `clamav` | Groupe propriétaire de la socket |
| `LocalSocketMode` | `666` | Permissions de la socket, voir ci-dessous |
| `User` | `clamav` | Compte de service non privilégié |
| `LogFile` | `/var/log/clamav/clamav.log` | Journal du démon |
| `TCPSocket` | **absente** | Aucune écoute réseau |

L'absence de `TCPSocket` est le point le plus important : le démon n'ouvre aucun port et n'est donc pas joignable depuis le réseau `10.2.101.0/24`. La surface d'attaque se limite à la machine elle-même.

#### Remarque sur les permissions de la socket

La valeur `LocalSocketMode 666` signifie que **tout utilisateur local** du poste peut écrire dans la socket, et donc demander une analyse au démon. Ce n'est pas la configuration la plus restrictive possible, mais c'est le réglage par défaut de Debian et il est cohérent avec l'usage visé :

- Sur un **poste de travail**, c'est ce qui permet à un utilisateur du domaine comme `jfernandes@ad.jcorp` d'analyser un fichier sans privilèges particuliers, et c'est une condition de fonctionnement de l'interface graphique ClamUI installée à l'étape 6.
- Sur un **serveur**, on resserrerait ce réglage à `660` en s'appuyant sur `LocalSocketGroup`, de façon à n'autoriser que les comptes explicitement ajoutés au groupe `clamav`, par exemple celui du serveur web.

Le risque résiduel sur un poste reste mesuré : un utilisateur local peut solliciter le moteur, pas en modifier la configuration ni lire des fichiers auxquels il n'a pas déjà accès. Je retiens donc le réglage par défaut et je documente l'arbitrage.

Enfin, `clamdscan --version` répond `ClamAV 1.4.3/28181/Thu Nov 12 07:27:14 2026`, soit exactement la même version et la même base qu'à l'étape 1. La nuance est importante : cette information n'est plus produite par un moteur chargé pour l'occasion, elle est **renvoyée par le démon**. Le dialogue entre le client et le service est donc opérationnel.

![Configuration de la socket locale et dialogue avec le démon](images/etape2-socket-locale.png)

### 3.7 Contrôles de fin d'étape

| Contrôle | Résultat attendu | Résultat observé | Conforme |
| --- | --- | --- | --- |
| Service actif | `active (running)` | `active (running)` depuis 09:55:48 | Oui |
| Démarrage automatique | `enabled` | `enabled` | Oui |
| Compte d'exécution | Utilisateur non privilégié | `clamav` pour `clamd` et `freshclam` | Oui |
| Pas d'écoute réseau | Aucune directive `TCPSocket` | Absente, seule `LocalSocket` est définie | Oui |
| Dialogue client/démon | Version renvoyée par le démon | `ClamAV 1.4.3/28181` | Oui |
| Coût mémoire | De l'ordre de 1 Gio | 947,4 Mio, soit 0,9 Gio mesuré | Oui |

---

## 4. Étape 3 — Test de détection avec EICAR

### 4.1 Qu'est-ce que le fichier EICAR ?

Le fichier EICAR, du nom de l'*European Institute for Computer Antivirus Research*, est un **faux virus de test**. C'est un simple fichier texte qui ne contient aucun code malveillant, mais dont la chaîne de caractères est reconnue comme virus de test par la quasi-totalité des antivirus, ClamAV compris. Il permet donc de vérifier qu'une chaîne de détection complète fonctionne — scan, journalisation, alerte, quarantaine — sans jamais manipuler un véritable logiciel malveillant.

C'est la bonne pratique : on ne teste jamais un antivirus avec un vrai échantillon sur une machine de production ou de laboratoire reliée au réseau de l'entreprise.

> **Remarque sur ce dépôt :** la chaîne EICAR n'est volontairement pas recopiée telle quelle dans ce rapport, et le fichier `eicar.txt` est exclu par le `.gitignore`. Un dépôt contenant la signature complète serait signalé comme infecté par l'antivirus de tout poste qui le clone. Les commandes du TP reconstituent la chaîne par concaténation, ce qui produit exactement le même fichier au moment de l'exécution.

### 4.2 Préparation des fichiers de test

Je travaille dans un dossier dédié, de façon à ne rien supprimer d'autre lors du test de remédiation, et je crée **deux** fichiers : un faux virus et un fichier sain. Le second sert de témoin : il prouve que l'antivirus distingue les fichiers au lieu de tout signaler.

```bash
mkdir -p ~/tp-clamav && cd ~/tp-clamav
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-ST' 'ANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt
echo 'Ceci est un fichier sain de test.' > sain.txt ; ls -l
```

**Résultat observé :** `eicar.txt` de **68 octets** et `sain.txt` de 34 octets, dans `/home/administrateur/tp-clamav`.

La taille de 68 octets est la taille canonique du fichier EICAR, ce qui confirme que la reconstitution par concaténation a bien produit la chaîne attendue.

![Création des fichiers de test](images/etape3-creation-fichiers.png)

### 4.3 Détection sans suppression

Je commence par une analyse qui se contente de signaler, sans rien supprimer.

```bash
clamscan --infected --recursive ~/tp-clamav
```

| Option | Effet |
| --- | --- |
| `--infected` | N'affiche que les fichiers détectés |
| `--recursive` | Parcourt les sous-répertoires |

**Résultat observé :**

```
/home/administrateur/tp-clamav/eicar.txt: Eicar-Test-Signature FOUND
```

| Indicateur du résumé | Valeur |
| --- | --- |
| Signatures connues | 3 628 258 |
| Version du moteur | 1.4.3 |
| Répertoires analysés | 1 |
| Fichiers analysés | 2 |
| **Fichiers infectés** | **1** |
| Durée | 15,6 s |

Les deux fichiers ont été analysés et un seul est signalé : `sain.txt` n'apparaît pas, ce qui est le comportement attendu. Le nom de signature renvoyé est `Eicar-Test-Signature`, là où le tutoriel de référence mentionne `Eicar-Signature` : la dénomination a évolué entre les versions de la base, sans conséquence sur la détection.

![Détection du fichier EICAR](images/etape3-scan-eicar.png)

### 4.4 Comparaison de `clamscan` et de `clamdscan`

Le tableau du chapitre 1 oppose les deux outils sur le papier. Je vérifie ici l'écart réellement mesuré sur la machine, sur **le même fichier**.

```bash
time clamscan ~/tp-clamav/eicar.txt
time clamdscan --fdpass ~/tp-clamav/eicar.txt
```

L'option `--fdpass` transmet au démon le descripteur du fichier plutôt que son chemin. Elle est nécessaire ici : le démon tourne sous le compte `clamav` et n'a pas forcément accès au dossier personnel d'un utilisateur, alors que le descripteur, lui, est ouvert par le client qui dispose déjà des droits.

**Résultat observé :**

| Mesure | `clamscan` | `clamdscan --fdpass` |
| --- | --- | --- |
| Temps réel | **17,955 s** | **0,045 s** |
| Temps processeur utilisateur | 16,288 s | 0,011 s |
| Durée d'analyse annoncée | 17,929 s | 0,014 s |
| Détection | `Eicar-Test-Signature FOUND` | `Eicar-Test-Signature FOUND` |

Le rapport est d'environ **400 pour 1** sur un fichier de 68 octets.

La sortie de `clamscan` explique précisément d'où vient l'écart, puisqu'elle détaille sa phase de démarrage :

```
Loading:    14s   3.63M/3.63M sigs
Compiling:   3s   41/41 tasks
```

Soit 17 secondes consacrées au **chargement et à la compilation des signatures**, et une fraction de seconde à l'analyse elle-même. `clamscan` refait ce travail à chaque exécution, tandis que `clamdscan` interroge un démon qui a déjà tout en mémoire — ce qui est exactement ce que coûtent les 947 Mio mesurés à l'étape 2.

**Conséquence pratique pour l'exploitation :** le choix entre les deux outils n'est pas une affaire de préférence.

- Une analyse **fréquente ou déclenchée à la demande** doit passer par `clamdscan`, sinon chaque appel paie 17 secondes de chargement. C'est le cas du script lancé toutes les quelques minutes, de l'analyse d'un fichier déposé, ou d'un clic dans une interface graphique.
- Une analyse **massive et planifiée la nuit** peut utiliser `clamscan` : les 17 secondes de chargement sont négligeables devant la durée totale, et cela évite de maintenir un démon résident de près de 1 Gio sur une machine qui n'en a pas l'usage le reste du temps.

![Comparaison des temps d'analyse](images/etape3-comparaison-scan.png)

### 4.5 Suppression du fichier détecté et journalisation

```bash
clamscan --infected --remove --recursive ~/tp-clamav ; ls -l ~/tp-clamav
sudo tail -n 15 /var/log/clamav/clamav.log
```

L'option `--remove` supprime les fichiers détectés. Elle est employée ici sur un dossier de test ne contenant qu'un faux virus ; en exploitation réelle, on lui préfère `--move` vers une quarantaine, ce qui est mis en place à l'étape suivante.

**Résultat observé :** `eicar.txt: Removed.`, et le `ls` ne laisse plus que `sain.txt`. La détection débouche donc bien sur une remédiation effective, et le fichier sain n'a pas été touché.

#### Observation : toutes les analyses ne sont pas journalisées

Le journal `/var/log/clamav/clamav.log` relevé à l'étape 2 contient bien une trace de détection :

```
Thu Nov 12 10:01:36 2026 -> /home/administrateur/tp-clamav/eicar.txt:
Eicar-Test-Signature(44d88612fea8a8f36de82e1278abb02f:68) FOUND
```

L'entrée précise l'empreinte MD5 du fichier et sa taille en octets, ce qui permet d'identifier précisément l'élément détecté.

Mais en comparant les horodatages, un constat s'impose : **une seule des quatre analyses figure dans ce journal**, celle de 10:01:36, qui correspond exactement à l'exécution de `clamdscan`. Les trois analyses lancées avec `clamscan` (à 10:00:43, 10:01:13 et 10:01:51) n'y apparaissent pas.

L'explication tient à l'architecture décrite au chapitre 1 : ce fichier est le journal **du démon**. `clamscan` est un scanner autonome qui n'a aucun lien avec `clamd` ; il écrit sur la sortie standard et ne journalise que si on le lui demande explicitement avec l'option `--log`.

C'est un point à retenir pour l'exploitation : une détection faite par `clamscan` sans `--log` **ne laisse aucune trace** une fois le terminal fermé. Toute analyse planifiée devra donc écrire dans un fichier dédié, ce que je mets en place à l'étape 5.

Les lignes précédentes du journal, horodatées à 09:56:02, correspondent au démarrage du démon et énumèrent les formats pris en charge : exécutables Windows (`Portable Executable`), `ELF`, courriels, `OLE2`, `PDF`, `SWF`, `HTML`, `XMLDOCS`, `HWP3` et `OneNote`. Le démon signale également une auto-vérification toutes les 3 600 secondes, mécanisme par lequel il recharge ses signatures lorsque `freshclam` en a téléchargé de nouvelles — sans quoi la mise à jour des bases n'atteindrait jamais le processus résident.

![Suppression du fichier détecté et journal du démon](images/etape3-suppression-journal.png)

### 4.6 Contrôles de fin d'étape

| Contrôle | Résultat attendu | Résultat observé | Conforme |
| --- | --- | --- | --- |
| Détection | Le faux virus est signalé | `Eicar-Test-Signature FOUND` | Oui |
| Absence de faux positif | Le fichier sain n'est pas signalé | `sain.txt` jamais détecté ni supprimé | Oui |
| Remédiation | Le fichier détecté est supprimé | `Removed.`, confirmé par `ls` | Oui |
| Journalisation | La détection est tracée | Entrée avec empreinte MD5 et taille, pour l'analyse passée par le démon | Oui, avec la réserve ci-dessus |
| Écart de performance | `clamdscan` nettement plus rapide | 0,045 s contre 17,955 s, soit un rapport de 400 | Oui |

---

## 5. Étape 4 — Protection en temps réel et quarantaine

_Section à compléter._

---

## 6. Étape 5 — Analyse planifiée

_Section à compléter._

---

## 7. Étape 6 — Interface graphique ClamUI

### 7.1 Ce qu'est ClamUI

ClamAV ne dispose pas d'interface graphique officielle. ClamUI est un projet open source construit avec GTK et libadwaita, qui s'intègre nativement à un bureau GNOME comme celui de la VM 702. Il ne s'agit **pas** d'un second moteur antivirus : ClamUI est une surcouche qui appelle `clamscan`, `clamdscan`, `freshclam` et `clamonacc` à la place de l'utilisateur et présente les résultats dans une interface lisible, avec en plus un tableau de bord d'audit de sécurité du système.

Son intérêt dans le contexte JCorp est précisément celui d'un poste de travail : un utilisateur comme Joshua Fernandes doit pouvoir analyser une clé USB ou un téléchargement sans ouvrir de terminal.

### 7.2 Version retenue et écart avec le tutoriel

Le tutoriel suivi décrit la version **0.2.0** et signale deux difficultés : un défaut d'élévation de privilèges sur la distribution Flatpak, et un paquet `.deb` qui refuse de s'installer sur Debian 13 parce que sa dépendance `policykit-1` n'existe plus dans cette version de la distribution.

Je retiens donc la version **0.6.0**, publiée le 11 novembre 2026, qui règle ce point en séparant l'application et son composant privilégié en deux paquets distincts :

| Paquet | Rôle |
| --- | --- |
| `clamui_0.6.0_amd64.deb` | Application de bureau |
| `clamui-privileged-helper_0.6.0_amd64.deb` | Composant privilégié, nécessaire aux opérations demandant une élévation (configuration du temps réel, écriture de `clamd.conf`) |

L'installation par Flatpak est écartée pour cette raison. Cet écart avec le tutoriel est assumé et documenté : reprendre la version du tutoriel aurait conduit à un échec d'installation sur Debian 13.

_Section à compléter._

---

## 8. Étape 7 — Recette

Tableau de validation à compléter au fur et à mesure. Un contrôle n'est déclaré conforme que si sa preuve est enregistrée.

| N° | Contrôle | Résultat attendu | Résultat | Preuve |
| --- | --- | --- | --- | --- |
| 1 | Moteur installé | Version de `clamscan` affichée | **Conforme** — ClamAV 1.4.3, paquets `1.4.3+dfsg-1` à l'état `ii` | `etape1-version-moteur.png` |
| 2 | Signatures présentes | Trois bases `.cvd` dans `/var/lib/clamav/` | **Conforme** — 108 Mio, environ 3,64 millions de signatures, base du jour | `etape1-freshclam-controles.png` |
| 3 | Mise à jour automatique | `clamav-freshclam` `enabled` et `active` | **Conforme** | `etape1-freshclam-controles.png` |
| 4 | Démon opérationnel | `clamav-daemon` `active (running)` | **Conforme** — PID 6348, 947,4 Mio, sous le compte `clamav` | `etape2-daemon-status.png` |
| 4 bis | Exposition réseau du démon | Aucune écoute TCP | **Conforme** — socket locale uniquement | `etape2-socket-locale.png` |
| 5 | Détection à la demande | EICAR détecté par `clamscan` | **Conforme** — `Eicar-Test-Signature FOUND`, fichier sain non signalé | `etape3-scan-eicar.png` |
| 5 bis | Remédiation | Le fichier détecté est supprimé | **Conforme** — `Removed.` | `etape3-suppression-journal.png` |
| 5 ter | Écart `clamscan` / `clamdscan` | Le client du démon est plus rapide | **Conforme** — 0,045 s contre 17,955 s | `etape3-comparaison-scan.png` |
| 6 | Détection en temps réel | EICAR détecté et déplacé en quarantaine dès son écriture | _à renseigner_ | _à produire_ |
| 7 | Journalisation | Détection tracée dans le journal correspondant | **Conforme** — empreinte MD5 et taille dans `clamav.log` ; `clamscan` ne journalise pas sans `--log` | `etape3-suppression-journal.png` |
| 8 | Analyse planifiée | *Timer* actif et prochaine exécution affichée | _à renseigner_ | _à produire_ |
| 9 | Interface graphique | ClamUI lancé, état du moteur et des signatures affiché | _à renseigner_ | _à produire_ |
| 10 | Scan depuis l'interface | Analyse déclenchée et résultat affiché dans ClamUI | _à renseigner_ | _à produire_ |

---

## 9. Limites et conclusion

_Section à rédiger en fin de TP. Points à traiter :_

- ClamAV repose principalement sur des signatures : il est efficace sur les menaces connues, mais nettement moins sur les attaques du jour et les variantes fortement obfusquées. Ce n'est pas un EDR.
- L'outil est conçu avant tout pour des serveurs Linux ; sur un poste de travail il apporte une protection utile mais partielle.
- Le coût en CPU, en mémoire et en temps d'analyse est réel, ce qu'illustre concrètement la contrainte de mémoire rencontrée sur la VM 702.
- ClamAV doit être considéré comme une brique parmi d'autres, aux côtés du filtrage en amont, du durcissement du système, du contrôle des accès et de la sensibilisation des utilisateurs.
- Prolongement possible dans le projet JCorp : remonter l'état de l'antivirus et les détections vers la supervision Grafana/Prometheus prévue en atelier professionnel 1, afin de ne plus dépendre d'un contrôle poste par poste.

---

[Retour à la présentation du TP](README.md)
