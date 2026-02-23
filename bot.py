"""
Discord Ecosystem Mapper - Selfbot Edition
Layer-by-layer BFS. Creates nodes for unreachable servers (expired/captcha).

New flags:
  --keywords      Comma-separated partner channel keywords (overrides defaults)
  --scan-byod     Scrape BYOD/server IPs from matching channels into a txt file
  --scan-ubg      Scrape URLs from advertising channels into a txt file
  --byod-output   Output path for BYOD IP list  (default: byod_ips.txt)
  --ubg-output    Output path for UBG/ad URL list (default: ubg_links.txt)
  --scan-forums   Also crawl forum channels for invites/IPs/URLs (default: on)

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

# ─── Default Config ───────────────────────────────────────────────────────────

DEFAULT_PARTNER_KEYWORDS = [
    "partner", "partners", "affiliates", "affiliate", "collab",
    "collaboration",
]

# Channel name keywords that likely contain BYOD / server IPs
BYOD_CHANNEL_KEYWORDS = [
    "byod", "ip", "ips", "server-ip", "server-ips", "serverip",
    "game-server", "game-servers", "gameserver", "servers",
    "connect", "connection", "host", "hosting",
]

# Channel name keywords that likely contain advertising / UBG links
AD_CHANNEL_KEYWORDS = [
    "advertis", "ads", "ad-", "-ads", "promo", "promote",
    "self-promo", "selfpromo", "promotion", "links", "websites",
    "sites", "ubg", "unblocked", "games", "resources",
]

# ─── Regexes ──────────────────────────────────────────────────────────────────

INVITE_REGEX = re.compile(
    r"(?:https?://)?(?:www\.)?(?:discord\.gg|discord\.com/invite|discordapp\.com/invite)"
    r"/([a-zA-Z0-9\-]+)"
)

# Matches IPv4 with optional :port — e.g. 192.168.1.1, 104.21.44.12:25565
IP_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?::\d{1,5})?\b"
)

# Matches any http/https URL
URL_REGEX = re.compile(r"https?://[^\s<>\"')\]]+")

# ─── Node status values ───────────────────────────────────────────────────────

STATUS_OK         = "ok"        # joined and scanned
STATUS_CAPTCHA    = "captcha"   # could not join - captcha required
STATUS_EXPIRED    = "expired"   # invite was invalid/expired, no guild info
STATUS_FORBIDDEN  = "forbidden" # verification level too high / banned
STATUS_GHOST      = "ghost"     # got guild info but couldn't join for other reason

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
    def __init__(self, graph, max_depth, rate_delay,
                 partner_keywords=None,
                 scan_byod=False, byod_output="byod_ips.txt",
                 scan_ubg=False,  ubg_output="ubg_links.txt",
                 scan_forums=True):
        super().__init__()
        self.graph           = graph
        self.max_depth       = max_depth
        self.rate_delay      = rate_delay
        self.partner_keywords = partner_keywords or DEFAULT_PARTNER_KEYWORDS
        self.scan_byod       = scan_byod
        self.byod_output     = byod_output
        self.scan_ubg        = scan_ubg
        self.ubg_output      = ubg_output
        self.scan_forums     = scan_forums

        # Collected results (de-duplicated)
        self.found_ips       = {}   # ip_str -> {"ip": .., "server": .., "channel": .., "count": n}
        self.found_urls      = {}   # url -> {"url": .., "server": .., "channel": ..}

    # ── on_ready ─────────────────────────────────────────────────────────────

    async def on_ready(self):
        log(f"Logged in as {self.user} ({self.user.id})")
        if self.partner_keywords != DEFAULT_PARTNER_KEYWORDS:
            log(f"  Partner keywords: {', '.join(self.partner_keywords)}")
        if self.scan_byod:
            log(f"  BYOD IP scan    : ON  -> {self.byod_output}")
        if self.scan_ubg:
            log(f"  UBG/Ad URL scan : ON  -> {self.ubg_output}")
        if self.scan_forums:
            log(f"  Forum scanning  : ON")
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

                    # ── Optional extra scans (never affect the map) ──
                    if self.scan_byod:
                        await self.scan_byod_channels(guild)

                    if self.scan_ubg:
                        await self.scan_ad_channels(guild)

                elif gid and not joined:
                    self.graph.visited_guilds.add(gid)

                self.graph.save()
                self._save_lists()
                await asyncio.sleep(self.rate_delay)

            log(f"\n  Layer {depth} complete. {len(next_layer)} server(s) -> layer {depth+1}.")
            current_layer = next_layer

        self._finalize_edges()
        self.graph.save()
        self._save_lists()

        log(f"\n{'='*50}")
        log(f"CRAWL COMPLETE")
        log(f"  Servers mapped : {len(self.graph.nodes)}")
        log(f"  Connections    : {len(self.graph.edges)}")
        if self.scan_byod:
            log(f"  BYOD IPs found : {len(self.found_ips)}")
        if self.scan_ubg:
            log(f"  UBG URLs found : {len(self.found_urls)}")
        log(f"{'='*50}")
        await self.close()

    # ── Resolve invite ────────────────────────────────────────────────────────

    async def resolve_invite(self, invite_code, source_id):
        """
        Returns (guild_id, joined: bool).
        Always tries to create a node with whatever info is available.
        joined=True  -> we're in the server and can scan it
        joined=False -> unreachable but node still created
        """
        invite_url = f"https://discord.gg/{invite_code}"

        try:
            invite = await self.fetch_invite(invite_code, with_counts=True)
            gid = str(invite.guild.id)
        except discord.errors.NotFound:
            log(f"  [x] Expired/invalid invite, no server info: {invite_code}")
            return None, False
        except Exception as e:
            log(f"  [!] Could not fetch invite {invite_code}: {e}")
            return None, False

        gid = str(invite.guild.id)

        if gid in self.graph.visited_guilds:
            log(f"  [=] Already visited: {invite.guild.name}")
            if source_id:
                self.graph.add_edge(source_id, gid, "cross-link")
            return gid, False

        existing = self.get_guild(invite.guild.id)
        if existing:
            log(f"  [=] Already in guild: {existing.name}")
            self.graph.add_node_from_guild(existing, invite=invite_url, status=STATUS_OK)
            if source_id:
                self.graph.add_edge(source_id, gid, "discovery")
            return gid, True

        try:
            log(f"  Joining: {invite.guild.name}")
            await asyncio.sleep(1.5)
            await invite.accept()

            for _ in range(15):
                guild = self.get_guild(invite.guild.id)
                if guild:
                    self.graph.add_node_from_guild(guild, invite=invite_url, status=STATUS_OK)
                    if source_id:
                        self.graph.add_edge(source_id, gid, "discovery")
                    log(f"  [+] Joined: {guild.name} ({getattr(guild, 'member_count', '?')} members)")
                    return gid, True
                await asyncio.sleep(1)

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
                label  = "captcha required"
            elif "forbidden" in ename.lower() or "verification" in err_str:
                status = STATUS_FORBIDDEN
                label  = "verification too high"
            else:
                status = STATUS_GHOST
                label  = f"{ename}: {e}"

            self.graph.add_node_from_invite(invite, status=status)
            if source_id:
                self.graph.add_edge(source_id, gid, "discovery")
            log(f"  [*] Unreachable ({label}): {invite.guild.name} -- node created anyway")
            return gid, False

    # ── Helpers: channel/forum iteration ─────────────────────────────────────

    def _matching_text_channels(self, guild, keywords):
        """Text channels whose names contain any of the given keywords."""
        return [
            ch for ch in guild.text_channels
            if any(kw in ch.name.lower() for kw in keywords)
        ]

    def _matching_forum_channels(self, guild, keywords):
        """Forum channels whose names contain any of the given keywords."""
        if not self.scan_forums:
            return []
        try:
            return [
                ch for ch in guild.channels
                if isinstance(ch, discord.ForumChannel)
                and any(kw in ch.name.lower() for kw in keywords)
            ]
        except Exception:
            return []

    async def _iter_text_channel(self, channel, limit=300):
        """Yield messages from a text channel, swallowing permission errors."""
        try:
            async for msg in channel.history(limit=limit):
                yield msg
            await asyncio.sleep(0.8)
        except discord.errors.Forbidden:
            log(f"    #{channel.name}: no access")
        except Exception as e:
            log(f"    #{channel.name}: error - {e}")

    async def _iter_forum_channel(self, forum, limit_threads=30, limit_msgs=100):
        """Yield messages from a forum channel's active threads."""
        try:
            threads = list(forum.threads)[:limit_threads]
            log(f"    #{forum.name} (forum): {len(threads)} active thread(s)")
            for thread in threads:
                try:
                    async for msg in thread.history(limit=limit_msgs):
                        yield msg
                    await asyncio.sleep(0.5)
                except discord.errors.Forbidden:
                    pass
                except Exception as e:
                    log(f"      thread {thread.name}: error - {e}")
        except Exception as e:
            log(f"    #{forum.name} (forum): error - {e}")

    # ── Scan partner channels (for map building) ──────────────────────────────

    async def scan_partner_channels(self, guild, guild_id):
        found     = []
        seen_here = set()

        text_channels = self._matching_text_channels(guild, self.partner_keywords)

        if not text_channels:
            log(f"  [~] No partner channels found, scanning first 5 text channels")
            text_channels = list(guild.text_channels)[:5]
        else:
            names = ", ".join(f"#{c.name}" for c in text_channels)
            log(f"  [S] Partner channels: {names}")

        # Text channels
        for channel in text_channels:
            ch_count = 0
            async for msg in self._iter_text_channel(channel, limit=300):
                for match in INVITE_REGEX.finditer(msg.content):
                    code = match.group(1)
                    if code not in seen_here:
                        seen_here.add(code)
                        found.append((code, channel.name))
                        ch_count += 1
            if ch_count:
                log(f"    #{channel.name}: {ch_count} unique invite(s)")

        # Forum channels matching partner keywords
        forum_channels = self._matching_forum_channels(guild, self.partner_keywords)
        for forum in forum_channels:
            ch_count = 0
            async for msg in self._iter_forum_channel(forum):
                for match in INVITE_REGEX.finditer(msg.content):
                    code = match.group(1)
                    if code not in seen_here:
                        seen_here.add(code)
                        found.append((code, forum.name))
                        ch_count += 1
            if ch_count:
                log(f"    #{forum.name} (forum): {ch_count} unique invite(s)")

        return found

    # ── Scan BYOD / IP channels ───────────────────────────────────────────────

    async def scan_byod_channels(self, guild):
        """
        Scans channels matching BYOD_CHANNEL_KEYWORDS for IPv4 addresses.
        Results are stored in self.found_ips — NOT added to the map.
        """
        guild_name   = guild.name
        text_channels  = self._matching_text_channels(guild, BYOD_CHANNEL_KEYWORDS)
        forum_channels = self._matching_forum_channels(guild, BYOD_CHANNEL_KEYWORDS)

        if not text_channels and not forum_channels:
            return

        names = ", ".join(f"#{c.name}" for c in text_channels + forum_channels)
        log(f"  [IP] Scanning BYOD channels: {names}")

        total = 0

        for channel in text_channels:
            async for msg in self._iter_text_channel(channel, limit=500):
                for match in IP_REGEX.finditer(msg.content):
                    ip = match.group(0)
                    if ip not in self.found_ips:
                        self.found_ips[ip] = {
                            "ip":      ip,
                            "server":  guild_name,
                            "channel": channel.name,
                            "count":   1,
                        }
                        total += 1
                    else:
                        self.found_ips[ip]["count"] += 1

        for forum in forum_channels:
            async for msg in self._iter_forum_channel(forum):
                for match in IP_REGEX.finditer(msg.content):
                    ip = match.group(0)
                    if ip not in self.found_ips:
                        self.found_ips[ip] = {
                            "ip":      ip,
                            "server":  guild_name,
                            "channel": forum.name,
                            "count":   1,
                        }
                        total += 1
                    else:
                        self.found_ips[ip]["count"] += 1

        if total:
            log(f"  [IP] Found {total} new IP(s) in {guild_name}")

    # ── Scan advertising / UBG channels ──────────────────────────────────────

    async def scan_ad_channels(self, guild):
        """
        Scans channels matching AD_CHANNEL_KEYWORDS for URLs.
        Results are stored in self.found_urls — NOT added to the map.
        """
        guild_name   = guild.name
        text_channels  = self._matching_text_channels(guild, AD_CHANNEL_KEYWORDS)
        forum_channels = self._matching_forum_channels(guild, AD_CHANNEL_KEYWORDS)

        if not text_channels and not forum_channels:
            return

        names = ", ".join(f"#{c.name}" for c in text_channels + forum_channels)
        log(f"  [URL] Scanning ad channels: {names}")

        total = 0

        for channel in text_channels:
            async for msg in self._iter_text_channel(channel, limit=500):
                for match in URL_REGEX.finditer(msg.content):
                    url = match.group(0).rstrip(".,;)")
                    # Skip Discord invites — those go on the map
                    if "discord.gg" in url or "discord.com/invite" in url:
                        continue
                    if url not in self.found_urls:
                        self.found_urls[url] = {
                            "url":     url,
                            "server":  guild_name,
                            "channel": channel.name,
                        }
                        total += 1

        for forum in forum_channels:
            async for msg in self._iter_forum_channel(forum):
                for match in URL_REGEX.finditer(msg.content):
                    url = match.group(0).rstrip(".,;)")
                    if "discord.gg" in url or "discord.com/invite" in url:
                        continue
                    if url not in self.found_urls:
                        self.found_urls[url] = {
                            "url":     url,
                            "server":  guild_name,
                            "channel": forum.name,
                        }
                        total += 1

        if total:
            log(f"  [URL] Found {total} new URL(s) in {guild_name}")

    # ── Save BYOD / UBG lists ─────────────────────────────────────────────────

    def _save_lists(self):
        """Write BYOD IP list and/or UBG URL list to disk if scans are enabled."""
        if self.scan_byod and self.found_ips:
            lines = [
                f"# GhostLink BYOD IP List — {datetime.now(timezone.utc).isoformat()}",
                f"# Total: {len(self.found_ips)} unique IPs",
                "",
            ]
            # Sort by count descending so most-mentioned IPs come first
            for entry in sorted(self.found_ips.values(), key=lambda x: -x["count"]):
                lines.append(
                    f"{entry['ip']:<25}  # seen {entry['count']}x  |  "
                    f"first in #{entry['channel']} @ {entry['server']}"
                )
            Path(self.byod_output).write_text("\n".join(lines), encoding="utf-8")
            log(f"  [OK] BYOD list saved -> {self.byod_output} ({len(self.found_ips)} IPs)")

        if self.scan_ubg and self.found_urls:
            lines = [
                f"# GhostLink UBG/Ad URL List — {datetime.now(timezone.utc).isoformat()}",
                f"# Total: {len(self.found_urls)} unique URLs",
                "",
            ]
            for entry in self.found_urls.values():
                lines.append(
                    f"{entry['url']}"
                    f"  # #{entry['channel']} @ {entry['server']}"
                )
            Path(self.ubg_output).write_text("\n".join(lines), encoding="utf-8")
            log(f"  [OK] UBG list saved -> {self.ubg_output} ({len(self.found_urls)} URLs)")

    # ── Clean up edges ────────────────────────────────────────────────────────

    def _finalize_edges(self):
        """Remove any remaining pending: edges and deduplicate."""
        seen  = set()
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
    parser.add_argument("--token",        required=True)
    parser.add_argument("--invite",       required=True)
    parser.add_argument("--depth",        type=int,   default=2)
    parser.add_argument("--delay",        type=float, default=3.0)
    parser.add_argument("--output",       default="ecosystem.json")
    # New args
    parser.add_argument("--keywords",     default="",
                        help="Comma-separated partner channel keywords (overrides defaults)")
    parser.add_argument("--scan-byod",    action="store_true",
                        help="Enable BYOD/IP scanning into a txt file")
    parser.add_argument("--byod-output",  default="byod_ips.txt")
    parser.add_argument("--scan-ubg",     action="store_true",
                        help="Enable UBG/ad URL scanning into a txt file")
    parser.add_argument("--ubg-output",   default="ubg_links.txt")
    parser.add_argument("--no-forums",    action="store_true",
                        help="Disable forum channel scanning")
    args = parser.parse_args()

    # Parse keywords
    if args.keywords.strip():
        partner_keywords = [k.strip() for k in args.keywords.split(",") if k.strip()]
    else:
        partner_keywords = DEFAULT_PARTNER_KEYWORDS

    graph = EcosystemGraph(output_file=args.output)
    graph.seen_invites.add(args.invite)

    log("Discord Ecosystem Mapper")
    log(f"Seed: {args.invite} | Max depth: {args.depth} | Delay: {args.delay}s")

    client = MapperClient(
        graph            = graph,
        max_depth        = args.depth,
        rate_delay       = args.delay,
        partner_keywords = partner_keywords,
        scan_byod        = args.scan_byod,
        byod_output      = args.byod_output,
        scan_ubg         = args.scan_ubg,
        ubg_output       = args.ubg_output,
        scan_forums      = not args.no_forums,
    )

    try:
        client.run(args.token)
    except discord.errors.LoginFailure:
        log("[ERROR] Invalid token. Use your USER token, not a bot token.")
        sys.exit(1)

if __name__ == "__main__":
    main()
