# Barking

Barking est une messagerie chiffrée de bout en bout. Elle fonctionne en mesh (Bluetooth LE, Wi-Fi, LoRa) et par des nœuds internet ouverts. Le projet est open source.

## État

Prototype : la bibliothèque `barking-core` (protocole et chiffrement) et le client en ligne de commande `barking-cli`. Les apps mobiles et le nœud `barking-node` ne sont pas encore là.

## Vérifier un binaire

Les binaires de `barking-cli` sont reproductibles à l'octet près, attestés par la CI GitHub et signés par le mainteneur. N'importe qui peut vérifier qu'un binaire correspond au code source public, et le recompiler soi-même. La procédure est dans [docs/VERIFYING.md](docs/VERIFYING.md).

Le mainteneur trouvera la procédure de publication dans [docs/RELEASING.md](docs/RELEASING.md).
