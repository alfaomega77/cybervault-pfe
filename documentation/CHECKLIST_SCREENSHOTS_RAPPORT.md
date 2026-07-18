# Checklist screenshots rapport — avant / après coupure de session
# Lab uniquement. Ne pas faire ça sur un bastion de production.

## Prérequis
- [ ] CyberVault up : http://localhost:8090
- [ ] JumpServer up : http://localhost (stack jms_*)
- [ ] SMTP déjà dans `.env` (emails)
- [ ] Un asset lab + compte SSH dans JumpServer
- [ ] Token API JumpServer (Settings → API keys / Service account)

## 1. Mode prudent d’abord (screenshots “dry-run”)
Garde `AISS_DRY_RUN=true`

| # | Où | Quoi capturer |
|---|-----|----------------|
| S1 | JumpServer | Session SSH ouverte, prompt visible |
| S2 | JumpServer | Commande dangereuse tapée (`rm -rf /tmp/demo-lab` — dossier jetable) |
| S3 | CyberVault → Décisions | Ligne risque élevé + action LOCK/KILL + statut **dry_run** |
| S4 | Email | Alerte reçue (si SMTP OK) |

## 2. Coupure réelle (screenshots “avant / après”)
**Uniquement lab.**

1. Dans `.env` :
   ```env
   AISS_DRY_RUN=false
   AISS_JUMPSERVER_URL=http://host.docker.internal
   AISS_JUMPSERVER_TOKEN=ton_token_api
   ```
2. Redémarrer :
   ```bash
   cd /Users/mac/Downloads/jumpserver-dev
   docker compose up -d --force-recreate backend
   curl -s http://127.0.0.1:8090/health   # doit montrer "dry_run": false
   ```
3. CyberVault → **Mon PAM** → URL + token → Intégrer
4. Ouvrir **une** session SSH lab dans JumpServer

| # | Où | Quoi capturer |
|---|-----|----------------|
| S5 | JumpServer | **AVANT** — session active |
| S6 | JumpServer | Commande destructive (lab) |
| S7 | CyberVault | Décision LOCK/KILL + statut **ok** (pas dry_run) |
| S8 | JumpServer | **APRÈS** — session terminée / déconnectée |
| S9 | Email | Alerte correspondante |

5. Remettre tout de suite :
   ```env
   AISS_DRY_RUN=true
   ```
   puis `docker compose up -d --force-recreate backend`

## 3. Si JumpServer est arrêté
```bash
cd ~/jumpserver-docker/swarm
docker compose -f docker-compose-network.yml -f docker-compose-redis.yml \
  -f docker-compose-mariadb.yml -f docker-compose.yml up -d
```

## 4. Si la session ne se coupe pas
- health encore `"dry_run": true` → env / recreate backend
- token API invalide → régénérer dans JumpServer
- URL JumpServer inaccessible depuis le conteneur CyberVault → utiliser `http://host.docker.internal` (Mac) ou l’IP Docker de `jms_web`/`jms_core`
- événement pas “live” → vérifier webhook / plugin / ou script `13-demo-sales-live.sh` (montre la décision, pas forcément le kill JS)

## Légende rapport (texte utile)
> Figure X — Session privilégiée active avant intervention.
> Figure Y — Décision CyberVault (LOCK_SESSION / KILL_SESSION).
> Figure Z — Session terminée après exécution (dry-run désactivé en lab).
