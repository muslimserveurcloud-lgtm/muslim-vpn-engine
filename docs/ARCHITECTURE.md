# MUSLIM VPN ENGINE

Projet indépendant : implémentation originale.

## Modules

- msc_core : sockets, DNS, gestion des connexions
- msc_transport : transport TCP et UDP
- msc_protocol : protocole MSC
- tests : tests unitaires et réseau
- config : configuration locale
- logs : journaux

## Principes

- aucun moteur VPN tiers intégré ;
- code source développé dans ce projet ;
- protocole documenté et versionné ;
- primitives cryptographiques reconnues ;
- tests explicites avant toute connexion réelle ;
- compatibilité Android ARMv7 recherchée.
