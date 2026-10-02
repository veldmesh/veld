# Divergences

Tracks known gaps between the current implementation and the target design
("blind directory" coordination model), and whether each is worth fixing.

| # | Divergence | Status |
|---|---|---|
| 1 | (reserved) | open |
| 2 | (reserved) | open |
| 3 | (reserved) | open |
| 4 | (reserved) | open |
| 5 | Stale peer entries never expire: `LastSeen` is tracked on every peer update but nothing removes lapsed registrations, so stale peers accumulate in the bbolt registry | **fixed** — `veld-coord` runs a periodic TTL sweep (`coord/server/sweep.go`) that prunes peers whose `LastSeen` is older than `--peer-ttl` (default 30 days, `0` disables); see `docs/DEVELOPMENT.md` § "Coord server peer TTL sweep" |
