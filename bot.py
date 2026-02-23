"""
Discord Ecosystem Mapper - Selfbot Edition
Layer-by-layer BFS. Creates nodes for unreachable servers (expired/captcha).

Setup:
  pip install discord.py-self
  python bot.py --token YOUR_USER_TOKEN --invite INVITE_CODE --depth 2
"""

import asyncio
import json
import re
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import discord  # discord.py-self

# ─── Config ──────────────────────────────────────────────────────────────────

PARTNER_CHANNEL_KEYWORDS = [
    "partner", "partners", "affiliates", "affiliate", "collab",
    "collaboration",
]

INVITE_REGEX = re.compile(
    r"(?:https?://)?(?:www\.)?(?:discord\.gg|discord\.com/invite|discordapp\.com/invite)"
    r"/([a-zA-Z0-9\-]+)"
)

# Node status values
STATUS_OK         = "ok"           # joined and scanned
STATUS_CAPTCHA    = "captcha"      # could not join - captcha required
STATUS_EXPIRED    = "expired"      # invite was invalid/expired, no guild info
STATUS_FORBIDDEN  = "forbidden"    # verification level too high / banned
STATUS_GHOST      = "ghost"        # got guild info but couldn't join for other reason

# ─── Logging (Windows-safe) ───────────────────────────────────────────────────

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"{ts}  {msg}"
    try:
        print(line, flush=True)
    except UnicodeEncodeError:
        print(line.encode("ascii", errors="replace").decode("ascii"), flush=True)
    try:
        with open("crawler.log", "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

# ─── Graph Data ───────────────────────────────────────────────────────────────

class EcosystemGraph:
    def __init__(self, output_file="ecosystem.json"):
        self.output_file = output_file
        self.nodes = {}
        self.edges = []
        self.visited_guilds = set()
        self.seen_invites = set()

    def add_node(self, guild_id, name, member_count=0, icon=None, invite=None, status=STATUS_OK):
        gid = str(guild_id)
        if gid not in self.nodes:
            self.nodes[gid] = {
                "id": gid,
                "name": name,
                "member_count": member_count or 0,
                "icon": icon,
                "invite": invite,
                "status": status,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
            }
        elif status != STATUS_OK:
            # Upgrade status info if we learn more
            self.nodes[gid]["status"] = self.nodes[gid].get("status") or status
        return gid

    def add_node_from_guild(self, guild, invite=None, status=STATUS_OK):
        return self.add_node(
            guild_id=guild.id,
            name=guild.name,
            member_count=getattr(guild, "member_count", 0),
            icon=str(guild.icon) if getattr(guild, "icon", None) else None,
            invite=invite,
            status=status,
        )

    def add_node_from_invite(self, invite, status=STATUS_GHOST):
        """Create a node from invite metadata alone (no guild join needed)."""
        g = invite.guild
        return self.add_node(
            guild_id=g.id,
            name=g.name,
            member_count=getattr(invite, "approximate_member_count", None)
                         or getattr(g, "member_count", 0),
            icon=str(g.icon) if getattr(g, "icon", None) else None,
            invite=f"https://discord.gg/{invite.code}",
            status=status,
        )

    def add_edge(self, source_id, target_id, channel_name):
        key = (str(source_id), str(target_id))
        for e in self.edges:
            if (e["source"], e["target"]) == key:
                return
        self.edges.append({
            "source": str(source_id),
            "target": str(target_id),
            "channel": channel_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def save(self):
        # Count by status
        status_counts = {}
        for n in self.nodes.values():
            s = n.get("status", "?")
            status_counts[s] = status_counts.get(s, 0) + 1

        data = {
            "meta": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "node_count": len(self.nodes),
                "edge_count": len(self.edges),
                "status_counts": status_counts,
            },
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
        }
        Path(self.output_file).write_text(json.dumps(data, indent=2), encoding="utf-8")
        status_str = " | ".join(f"{k}: {v}" for k, v in status_counts.items())
        log(f"  [OK] Saved {self.output_file} -- {len(self.nodes)} nodes ({status_str}), {len(self.edges)} edges")
        return data

# ─── Selfbot Client ───────────────────────────────────────────────────────────

class MapperClient(discord.Client):
    def __init__(self, graph, max_depth, rate_delay):
        super().__init__()
        self.graph = graph
        self.max_depth = max_depth
        self.rate_delay = rate_delay

    async def on_ready(self):
        log(f"Logged in as {self.user} ({self.user.id})")
        await self.crawl()

    # ── Core BFS ─────────────────────────────────────────────────────────────

    async def crawl(self):
        seed_code = list(self.graph.seen_invites)[0]
        current_layer = [(seed_code, None)]

        for depth in range(self.max_depth + 1):
            if not current_layer:
                log(f"\nLayer {depth}: nothing to process, stopping.")
                break

            log(f"\n{'='*50}")
            log(f"LAYER {depth}  ({len(current_layer)} server(s) to process)")
            log(f"{'='*50}")

            next_layer = []

            for idx, (invite_code, source_id) in enumerate(current_layer, 1):
                log(f"\n  [{idx}/{len(current_layer)}] invite: {invite_code}")

                gid, joined = await self.resolve_invite(invite_code, source_id)

                if gid and joined and gid not in self.graph.visited_guilds:
                    self.graph.visited_guilds.add(gid)
                    guild = self.get_guild(int(gid))

                    if depth < self.max_depth:
                        new_invites = await self.scan_partner_channels(guild, gid)
                        added = 0
                        for code, channel_name in new_invites:
                            if code not in self.graph.seen_invites:
                                self.graph.seen_invites.add(code)
                                next_layer.append((code, gid))
                                added += 1
                        log(f"  [>] {added} new server(s) queued for layer {depth+1}")
                    else:
                        log(f"  [~] Max depth, not scanning outbound links")

                elif gid and not joined:
                    # Unreachable — already created node in resolve_invite
                    self.graph.visited_guilds.add(gid)  # don't try again

                self.graph.save()
                await asyncio.sleep(self.rate_delay)

            log(f"\n  Layer {depth} complete. {len(next_layer)} server(s) -> layer {depth+1}.")
            current_layer = next_layer

        self._finalize_edges()
        self.graph.save()

        log(f"\n{'='*50}")
        log(f"CRAWL COMPLETE")
        log(f"  Servers mapped : {len(self.graph.nodes)}")
        log(f"  Connections    : {len(self.graph.edges)}")
        log(f"{'='*50}")
        await self.close()

    # ── Resolve invite: join if possible, ghost node if not ───────────────────

    async def resolve_invite(self, invite_code, source_id):
        """
        Returns (guild_id, joined: bool).
        Always tries to create a node with whatever info is available.
        joined=True  -> we're in the server and can scan it
        joined=False -> unreachable but node still created
        """
        invite_url = f"https://discord.gg/{invite_code}"

        # ── Step 1: fetch invite metadata (works even for expired invites sometimes) ──
        try:
            invite = await self.fetch_invite(invite_code, with_counts=True)
            gid = str(invite.guild.id)
        except discord.errors.NotFound:
            # Truly dead invite - no guild info at all
            log(f"  [x] Expired/invalid invite, no server info: {invite_code}")
            return None, False
        except Exception as e:
            log(f"  [!] Could not fetch invite {invite_code}: {e}")
            return None, False

        gid = str(invite.guild.id)

        # Already visited?
        if gid in self.graph.visited_guilds:
            log(f"  [=] Already visited: {invite.guild.name}")
            if source_id:
                self.graph.add_edge(source_id, gid, "cross-link")
            return gid, False  # no need to rejoin/rescan

        # Already in this guild from a previous session?
        existing = self.get_guild(invite.guild.id)
        if existing:
            log(f"  [=] Already in guild: {existing.name}")
            self.graph.add_node_from_guild(existing, invite=invite_url, status=STATUS_OK)
            if source_id:
                self.graph.add_edge(source_id, gid, "discovery")
            return gid, True

        # ── Step 2: attempt to join ───────────────────────────────────────────
        try:
            log(f"  Joining: {invite.guild.name}")
            await asyncio.sleep(1.5)
            await invite.accept()

            # Wait for guild to appear in cache
            for _ in range(15):
                guild = self.get_guild(invite.guild.id)
                if guild:
                    self.graph.add_node_from_guild(guild, invite=invite_url, status=STATUS_OK)
                    if source_id:
                        self.graph.add_edge(source_id, gid, "discovery")
                    log(f"  [+] Joined: {guild.name} ({getattr(guild, 'member_count', '?')} members)")
                    return gid, True
                await asyncio.sleep(1)

            # Joined but guild not in cache - ghost it
            self.graph.add_node_from_invite(invite, status=STATUS_GHOST)
            if source_id:
                self.graph.add_edge(source_id, gid, "discovery")
            log(f"  [?] Joined but guild not cached: {invite.guild.name}")
            return gid, False

        except Exception as e:
            ename = type(e).__name__
            err_str = str(e).lower()

            if "captcha" in ename.lower() or "captcha" in err_str:
                status = STATUS_CAPTCHA
                label = "captcha required"
            elif "forbidden" in ename.lower() or "verification" in err_str:
                status = STATUS_FORBIDDEN
                label = "verification too high"
            else:
                status = STATUS_GHOST
                label = f"{ename}: {e}"

            # Still create the node from invite metadata
            self.graph.add_node_from_invite(invite, status=status)
            if source_id:
                self.graph.add_edge(source_id, gid, "discovery")
            log(f"  [*] Unreachable ({label}): {invite.guild.name} -- node created anyway")
            return gid, False

    # ── Scan partner channels ─────────────────────────────────────────────────

    async def scan_partner_channels(self, guild, guild_id):
        found = []
        seen_here = set()

        partner_channels = [
            ch for ch in guild.text_channels
            if any(kw in ch.name.lower() for kw in PARTNER_CHANNEL_KEYWORDS)
        ]

        if not partner_channels:
            log(f"  [~] No partner channels, scanning first 5")
            partner_channels = list(guild.text_channels)[:5]
        else:
            names = ", ".join(f"#{c.name}" for c in partner_channels)
            log(f"  [S] Partner channels: {names}")

        for channel in partner_channels:
            ch_count = 0
            try:
                async for message in channel.history(limit=300):
                    for match in INVITE_REGEX.finditer(message.content):
                        code = match.group(1)
                        if code not in seen_here:
                            seen_here.add(code)
                            found.append((code, channel.name))
                            ch_count += 1
                log(f"    #{channel.name}: {ch_count} unique invite(s)")
                await asyncio.sleep(0.8)
            except discord.errors.Forbidden:
                log(f"    #{channel.name}: no access")
            except Exception as e:
                log(f"    #{channel.name}: error - {e}")

        return found

    # ── Clean up edges ────────────────────────────────────────────────────────

    def _finalize_edges(self):
        """Remove any remaining pending: edges and deduplicate."""
        seen = set()
        clean = []
        for e in self.graph.edges:
            if e["target"].startswith("pending:") or e["source"].startswith("pending:"):
                continue
            key = (e["source"], e["target"])
            if key not in seen:
                seen.add(key)
                clean.append(e)
        self.graph.edges = clean


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Discord Ecosystem Mapper (Selfbot)")
    parser.add_argument("--token", required=True)
    parser.add_argument("--invite", required=True)
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--delay", type=float, default=3.0)
    parser.add_argument("--output", default="ecosystem.json")
    args = parser.parse_args()

    graph = EcosystemGraph(output_file=args.output)
    graph.seen_invites.add(args.invite)

    log("Discord Ecosystem Mapper")
    log(f"Seed: {args.invite} | Max depth: {args.depth} | Delay: {args.delay}s")

    client = MapperClient(graph=graph, max_depth=args.depth, rate_delay=args.delay)

    try:
        client.run(args.token)
    except discord.errors.LoginFailure:
        log("[ERROR] Invalid token. Use your USER token, not a bot token.")
        sys.exit(1)

if __name__ == "__main__":
    main()