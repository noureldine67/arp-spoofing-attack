from scapy.all import Ether, ARP, srp, sniff, conf


def get_mac(ip):
    """
    Envoie une requête ARP à l'IP donnée pour obtenir son adresse MAC réelle.

    Arguments:
        ip (str): L'adresse IP à interroger.

    Returns:
        str: Adresse MAC réelle de la machine cible.

    Exceptions:
        IndexError: Si aucun appareil ne répond à la requête.
    """
    # Création d'une trame Ethernet + Requête ARP en broadcast
    p = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    result = srp(p, timeout=3, verbose=False)[0]  # Envoi et réception
    return result[0][1].hwsrc  # Extraction de l'adresse MAC source


def process(packet):
    """
    Fonction appelée pour chaque paquet sniffé.
    Elle vérifie les paquets ARP et détecte les incohérences de MAC.

    Arguments:
        packet (scapy.Packet): Paquet réseau capturé par Scapy.
    """
    # Vérifie que le paquet contient un segment ARP
    if packet.haslayer(ARP):
        # Opération 2 = ARP reply (réponse à "Qui a cette IP ?")
        if packet[ARP].op == 2:
            try:
                ip_source = packet[ARP].psrc  # Adresse IP source du paquet ARP
                real_mac = get_mac(ip_source)  # MAC réelle obtenue par requête active
                response_mac = packet[ARP].hwsrc  # MAC annoncée dans la réponse ARP

                # Comparaison des deux MAC
                if real_mac != response_mac:
                    print(
                        f"[ALERTE SPOOFING] IP : {ip_source}\n"
                        f"MAC réelle : {real_mac.upper()}\n"
                        f"MAC reçue  : {response_mac.upper()}\n"
                    )
            except IndexError:
                # Aucun appareil n'a répondu (firewall, IP inactive, etc.)
                pass


if __name__ == "__main__":
    import sys

    print("[*] Démarrage de la surveillance ARP...")
    print("[*] Appuyez sur Ctrl+C pour quitter.")

    # Récupération de l'interface réseau à surveiller (par défaut = iface active)
    try:
        iface = sys.argv[1]
    except IndexError:
        iface = conf.iface  # Interface par défaut

    print(f"[*] Surveillance sur l'interface : {iface}\n")

    try:
        # Capture de paquets ARP uniquement, sans les stocker
        sniff(store=False, prn=process, iface=iface, filter="arp")
    except PermissionError:
        print("[!] Erreur : permission refusée. Lancez le script avec sudo/root.")
    except KeyboardInterrupt:
        print("\n[+] Arrêt du script. À bientôt !")
