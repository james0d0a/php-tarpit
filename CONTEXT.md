# php_tarpit

A honeypot that pretends to be a PHP server vulnerable to php2shell (CVE-2026-109618 / CVE-2026-109619). It attracts scanners and exploit tools, keeps their exploit chains running, and records what they send.

## Language

**Scanner**:
Any automated client that probes for php2shell or exploits it, from passive version checks to full RCE tools.
_Avoid_: Attacker tool, bot

**Exploit chain**:
The ordered sequence of requests, tied to one PHP session, that a scanner sends to try to get code execution. It always sits inside an attack session.
_Avoid_: Attack, exploit run

**Stage**:
One step in an exploit chain that has a distinct purpose (for example heap pressure, leak, payload delivery). Fingerprinting is not a stage; it belongs to the attack session.
_Avoid_: Step, phase

**Intel capture**:
The main goal: keeping a scanner's exploit chain going as far as possible and recording every stage, especially the final payload.
_Avoid_: Logging, collection

**Tarpit**:
The optional secondary goal, off unless the operator enables it: wasting a scanner's time and resources once its exploit chain has no more intel to give.
_Avoid_: Stall, slowdown

**Chain fingerprint**:
The identity of an exploit chain, made of its stage sequence and its final payload. Two chains with the same chain fingerprint give no new intel, whatever their source.
_Avoid_: Signature, chain hash

**Execution check**:
A scanner's test of whether code execution worked, such as echoing a token or computing a hash, sent before or instead of the real payload.
_Avoid_: RCE probe, canary

**Chain catalog**:
The research record of every known exploit chain: its stages, what the scanner checks at each stage, what makes it give up, and its final payload.
_Avoid_: PoC notes, research doc

**Persona**:
The vulnerable PHP stack the sensor pretends to be: web server, SAPI, PHP version, and any application front (for example Apache + mod_php + PHP 8.3 + WordPress).
_Avoid_: Profile, disguise, fingerprint

**Matcher**:
A rule in a persona that recognises which stage of an exploit chain a request belongs to.
_Avoid_: Detector, signature, filter

**Responder**:
A named, built-in behaviour that a persona assigns to a stage to answer it convincingly.
_Avoid_: Handler, reply template

**PHP session**:
The emulated PHP session a scanner refers to with `PHPSESSID`, including any upload-progress state the persona pretends to hold for it.
_Avoid_: Session (unqualified)

**Attack session**:
All activity from one scanner source over a continuous period: its fingerprinting requests plus zero or more exploit chains.
_Avoid_: Visit, campaign, chain track

**Sensor**:
One deployed honeypot instance with a single persona.
_Avoid_: Node, honeypot instance

**Viewer**:
A read-only review tool, separate from the sensor, for browsing one sensor's captured data by attack session.
_Avoid_: GUI, dashboard, console, front end

**First sighting**:
The attack session in which a given request body content first appears on a sensor; every later session sending the same content has no first sighting for it.
_Avoid_: New payload, novel body

**Fleet**:
A group of sensors deployed independently, possibly each with a different persona.
_Avoid_: Cluster, swarm
