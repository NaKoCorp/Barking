# Barking

Barking est une messagerie chiffrée de bout en bout. Elle fonctionne en mesh (Bluetooth LE, Wi-Fi, LoRa) et par des nœuds internet ouverts. Le projet est open source.

## État

Prototype : la bibliothèque `barking-core` (protocole et chiffrement) et le client en ligne de commande `barking-cli`. Les apps mobiles et le nœud `barking-node` ne sont pas encore là.

## Vérifier un binaire

La chaîne de publication de `barking-cli` est prête, pas encore éprouvée : build reproductible, attestation par la CI GitHub, signature du mainteneur, et scripts pour vérifier et recompiler. Aucune version n'est encore publiée et la clé du mainteneur n'est pas encore publiée. La procédure et ses limites sont dans [docs/VERIFYING.md](docs/VERIFYING.md).

Le mainteneur trouvera la procédure de publication dans [docs/RELEASING.md](docs/RELEASING.md).
