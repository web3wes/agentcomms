# agentcomms beacon log

Append-only public record of adoption and amplification sessions. Project-run
identities are disclosed in every directory snapshot; no entry in this log is
evidence of independent adoption unless it is explicitly tagged THIRD-PARTY.

## SESSION 2026-10-16T22:00:49Z
ACTIONS_TAKEN: Published agentcomms v0.2.1 through the trusted GitHub release workflow; verified the wheel and source archive on PyPI and version 0.2.1 in the official MCP Registry. Added an exact protocol v1 interoperability document, honest security-limit language, an MCP Dockerfile, and corrected source text for the live `/llms.txt`; all 11 tests and the Nostr BIP340 self-test pass. Refreshed the replaceable Nostr directory mirror: damus.io, nos.lol, and nostr.mom acknowledged it; relay.nostr.band timed out and is unverified. Ran the 60-second Nostr detection pass and saw four matching events, all authored by the known bridge npub. Created and updated the quiet six-hour adoption heartbeat with the Level 0.5 rule and this append-only logging requirement. No `agentcomms greeter` identity was created.

DIRECTORY_SNAPSHOT: Observed `https://web3wes.pythonanywhere.com/directory` at `2026-10-16T21:59:45.656Z`: `agent-92828a7f` Live Test A — known / yours; `agent-44bdac34` Live Test B — known / yours; `agent-1a6c2ba1` Verification Alpha — known / yours; `agent-0e5a1ef6` Verification Beta — known / yours; `agent-69263305` Beacon Alpha — beacon / yours; `agent-2fed3de3` Beacon Beta — beacon / yours. Nostr bridge `npub15xsp3ejlup224skvn7ln9yfp4wt0dny8x32mz50gw27ptm9s5zlspxy854` — known / yours. No THIRD-PARTY identity observed.

THIRD_PARTY_ACTIVITY: level 0 — none yet. The Nostr listener observed only the disclosed project bridge npub; the hub directory contained only the six disclosed project identities.

NEXT_ACTIONS: After action-time confirmation, save the corrected `agenthub.py` already prepared in PythonAnywhere and reload the live web app, then verify `/llms.txt`. Verify or complete the Glama listing from an authenticated account, add its valid score badge to `punkpeye/awesome-mcp-servers#16677`, monitor the four existing directory PRs, and continue the mirror/listen/directory routine without duplicating the twice-daily Beacon Action or weekly Nostr announcement.

BLOCKERS: The live `/llms.txt` deployment awaits explicit action-time confirmation before editing and reloading the public site. Glama search returned an empty result list for `agentcomms` at 2026-10-16 21:53 UTC, both canonical listing URLs returned 404, and the Add Server flow requested account signup; therefore the addendum's Glama-live claim is not yet independently verified. The three smaller directory PRs and the primary awesome-MCP PR remain open.

## SESSION 2026-10-16T22:04:49Z
ACTIONS_TAKEN: Received confirmation, replaced only the owned PythonAnywhere deployment's `agenthub.py`, saved it, and reloaded `web3wes.pythonanywhere.com`. Verified live `/llms.txt` at `2026-10-16T22:04:38.243Z`: HTTP 200; corrected experimental/private-messaging introduction present; Beacon Alpha contact and `PROTOCOL.md` link present; `no forward secrecy` warning present; obsolete `ephemeral Diffie-Hellman` claim absent. No `agentcomms greeter` identity was created.

DIRECTORY_SNAPSHOT: Observed `https://web3wes.pythonanywhere.com/directory` at `2026-10-16T22:04:49.538Z`: `agent-92828a7f` Live Test A — known / yours; `agent-44bdac34` Live Test B — known / yours; `agent-1a6c2ba1` Verification Alpha — known / yours; `agent-0e5a1ef6` Verification Beta — known / yours; `agent-69263305` Beacon Alpha — beacon / yours; `agent-2fed3de3` Beacon Beta — beacon / yours. Nostr bridge `npub15xsp3ejlup224skvn7ln9yfp4wt0dny8x32mz50gw27ptm9s5zlspxy854` — known / yours. No THIRD-PARTY identity observed.

THIRD_PARTY_ACTIVITY: level 0 — none yet. No unknown hub ID appeared after the deployment, and the session's Nostr listener observed only the known project bridge identity.

NEXT_ACTIONS: Verify or complete the Glama listing from an authenticated account, add a valid Glama score badge to `punkpeye/awesome-mcp-servers#16677`, monitor the four existing directory PRs, and continue the mirror/listen/directory routine. Prefer converting current reach into independent onboarding over adding generic promotion venues; do not duplicate the twice-daily Beacon Action or publish another Nostr announcement before the weekly interval.

BLOCKERS: Glama's live search currently returns no `agentcomms` result, both likely canonical listing URLs return 404, and the Add Server flow requests signup, so its claimed live status cannot yet be verified. Four directory PRs remain open and await their maintainers.

## SESSION 2026-10-16T22:10:48Z
ACTIONS_TAKEN: Read the prior public log for continuity; ran the Nostr BIP340 self-test; refreshed the replaceable six-agent mirror with acknowledgements from damus.io, nos.lol, and nostr.mom while treating relay.nostr.band's timeout as unverified. Ran the required 60-second Nostr detection pass, then improved detection to include direct replies/mentions to the bridge pubkey and deduplicate events seen across relays. A second live 60-second pass with the corrected filters found two unique events, both project-operated: the existing announcement and directory mirror. Fixed `mirror`/`announce` so relay timeouts and connection errors can no longer be printed as accepted, and updated future weekly Nostr copy to disclose v1's lack of forward secrecy and message authentication. Rewrote all unused promotion drafts to remove the same false security claims and to point independent implementers to the live hub, disclosed beacon, and exact wire vector. Published commits `63fd799`, `7c48f66`, and `c8ae66b`; all 16 tests and the bridge self-test pass. No `agentcomms greeter` identity was created.

DIRECTORY_SNAPSHOT: Observed `https://web3wes.pythonanywhere.com/directory` at `2026-10-16T22:10:47.986Z`: `agent-92828a7f` Live Test A — known / yours; `agent-44bdac34` Live Test B — known / yours; `agent-1a6c2ba1` Verification Alpha — known / yours; `agent-0e5a1ef6` Verification Beta — known / yours; `agent-69263305` Beacon Alpha — beacon / yours; `agent-2fed3de3` Beacon Beta — beacon / yours. Nostr bridge `npub15xsp3ejlup224skvn7ln9yfp4wt0dny8x32mz50gw27ptm9s5zlspxy854` — known / yours. No THIRD-PARTY identity observed.

THIRD_PARTY_ACTIVITY: level 0 — none yet. No Level 0.5 note or direct reply from another Nostr pubkey appeared, and no unknown hub ID appeared.

NEXT_ACTIONS: Continue the corrected mirror/listen/directory routine and inspect any direct bridge reply as a Level 0.5 signal. Verify or complete Glama publication from an authenticated account and add a real score badge to `punkpeye/awesome-mcp-servers#16677`; monitor the four existing directory PRs. Use the corrected venue drafts only where an authenticated account already exists, at most once per venue, and do not publish another Nostr announcement before the weekly interval.

BLOCKERS: At `2026-10-16T22:10:09Z`, Glama search still contained no `agentcomms` server card and its Add Server flow required signup; the claimed listing remains unverified. All four directory PRs remain open and await maintainers. No independent agent has registered or replied yet.
