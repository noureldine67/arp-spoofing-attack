# ARP Spoofing & Detection - Scripts éducatifs

Ce projet contient deux scripts Python utilisant Scapy :

- `arpspoof.py` : pour réaliser une attaque ARP spoofing
- `arp_detect.py` : pour détecter une tentative de spoofing ARP

Attention : Ce projet est à but éducatif uniquement. Lancer ce type de script sur un réseau sans autorisation est illégal.


## 1. ARP Spoofing (attaque)

### Lancer le script

```bash
sudo python3 arp_spoofing_attack.py <IP_VICTIME> <IP_PASSERELLE> [-v]
```

### Exemple

```bash
sudo python3 arpspoof.py 192.168.1.10 192.168.1.1 -v
```

Ce script :

* Usurpe l'identité du routeur auprès de la victime
* Usurpe l'identité de la victime auprès du routeur
* Active le transfert IP pour permettre le relais du trafic entre les deux

---

## 2. Détection de spoofing ARP

### Lancer le script

```bash
sudo python3 arp_detect.py
```

### Exemple

```bash
sudo python3 arp_detect.py
```

Ce script :

* Écoute les paquets ARP sur le réseau
* Vérifie si les adresses MAC correspondent réellement à l’adresse IP annoncée
* Affiche une alerte en cas d’incohérence

---

## Explication rapide

### ARP Spoofing

Le script d'attaque envoie de fausses réponses ARP pour modifier la table ARP de la cible, redirigeant ainsi son trafic réseau.

### Détection

Le script de détection interroge activement les adresses IP présentes dans les paquets ARP pour valider l’adresse MAC réelle. Si elle ne correspond pas, il signale un spoofing.

---

## Avertissement

Ce projet est fourni à des fins pédagogiques uniquement, par exemple dans le cadre d’un cours ou d’un laboratoire de cybersécurité.
L'utilisation sur un réseau sans autorisation explicite constitue une infraction à la loi.

```