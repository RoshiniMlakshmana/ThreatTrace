# Block 17B — Speaker Notes

Simple spoken language for each slide in [docs/block17b-presentation-demo.md](block17b-presentation-demo.md)'s 14-slide outline. Roughly 30-60 seconds per slide. Don't read these verbatim — say them like you're explaining it to a colleague, not reading a paper.

## Opening (~30 seconds)

> "Security teams deal with a lot of disconnected work — someone finds a vulnerability, someone else tracks threat intel, someone else writes detection rules, and those three people often don't talk to each other in any structured way. I wanted to explore whether an AI-assisted system could connect those stages — discovery, intelligence, detection — without just handing an AI the keys and hoping for the best. So I built ThreatTrace: a research platform where an LLM proposes what to do, but every actual decision — what runs, what's allowed, what gets flagged for a human — goes through deterministic, testable code. Today I'll show you how it's built and walk through a real run against a local test target."

## Slide 1 — ThreatTrace
30s. Just the title and value line. Don't over-explain yet — this is the hook. "ThreatTrace connects vulnerability discovery, threat intelligence, and detection engineering, with deterministic controls sitting between every AI proposal and every action it could trigger."

## Slide 2 — Problem
45s. Talk through the disconnected-tools picture concretely: "A scanner finds something. It sits in a report. Separately, someone's tracking a CVE that's actively being exploited. Separately again, someone's supposed to write a detection rule for it. In practice these three things often never actually connect — nobody automatically asks 'can we even detect this with what we have?' before writing a rule, or 'does this finding actually matter given what we know is being exploited right now?'"

## Slide 3 — Research Question
30s. Read the question, then add: "I want to be upfront — this is exploratory work. I'm not claiming to have proven this is better than existing approaches. I'm showing you what was built and what it actually does, honestly, including where it falls short."

## Slide 4 — ThreatTrace Architecture
60s. Walk the diagram left to right: "On one side, there's an LLM layer — a small number of real Claude agents, six total, that propose plans and interpret results. Everything past that arrow is deterministic Python — no AI involved. Policy checks, a Security Governor, the actual tool adapters, threat intel ingestion, detection engineering, and a live dashboard. I want to be precise about that number — six real agents — because it's easy to inflate that kind of claim, and I'd rather undersell it."

## Slide 5 — Analyst-Governed AI Model
45s. "Here's the core pattern that repeats everywhere in this system: the LLM proposes something — a tool plan, a detection rule draft. Then policy code checks whether it's even allowed. Then a separate Governor decides based on role, scope, and a few other observable signals. Only then does deterministic code actually execute or validate anything. And at the end, a human still has to review it. The LLM never gets to skip any of those steps."

## Slide 6 — Bug Bounty Workflow
45s. "This is the offensive-discovery side. A planner proposes which tools to run — HTTP checks, Nmap, Nuclei, ZAP, or Burp if it's configured. Policy and Governor both have to agree before anything runs. Results get normalized into one common evidence format, then correlated into findings."

## Slide 7 — Multi-Tool Evidence Correlation
45s. "Here's a real example from our validation run. Two completely different tools — our HTTP checker and ZAP — both independently noticed the same target was missing a security header. Instead of reporting that as two separate findings, the correlation step recognized they were describing the same underlying issue and merged them into one finding, with both tools credited as sources. That's a real result, not a staged one."

## Slide 8 — Threat Intelligence Workflow
45s. "On the intelligence side, we pull from CISA's known-exploited-vulnerabilities catalog, NVD, and EPSS — all real, live, public sources. When two sources disagree — for example, KEV says a vulnerability is being actively exploited, but EPSS, which is just a probability score, doesn't itself confirm exploitation — the system flags that as 'conflicting' rather than quietly picking one. That's intentional; I'd rather surface disagreement than paper over it."

## Slide 9 — Intelligent Detection Engineering
60s. "This is where a finding — from either the bug bounty side or the threat intel side — can turn into a draft detection rule. But before anything gets drafted, there's a telemetry feasibility check: does the organization even have the logs needed to detect this behavior? If not, the system stops there and proposes zero rules. It doesn't write a rule just to have something to show. Only if telemetry is actually available does the LLM planner draft a rule, which then goes through deterministic validation before it's stored as a candidate."

## Slide 10 — Security Governor
45s. "This is the piece I want to spend a little extra time on, because it's the answer to 'why can't the AI just do it.' The Governor is a plain deterministic function — no AI — that looks at a fixed set of signals: what role is acting, what stage of the workflow, whether scope is being respected, whether something's trying to treat untrusted content as an instruction. Same function, same code path, whether the answer comes back allow or block. I'll show you both in a minute."

## Slide 11 — Live Platform
30s. "All of this runs through a small local backend and a real-time dashboard. It's bound to localhost only — this isn't something exposed to a network, it's a local research tool. It streams events live as a run progresses, so you can watch a workflow happen instead of just reading a final report."

## Slide 12 — Final Validation Results
45s. "These are the exact numbers from our final validation pass, not cherry-picked from an earlier, better-looking run. [Read 3-4 of the most interesting rows from the table — don't read all of them aloud.] I'll call out one thing specifically: Nuclei, one of our scanners, shows up as unavailable here, not because I hid a failure, but because that's honestly what happened, and I'll explain why in a moment."

## Slide 13 — What ThreatTrace Refuses To Fake
45s. "I think this slide matters more than it looks like it should. When Nuclei wasn't available, the system reported it as unavailable — it didn't pretend to run it. When there's no telemetry to support a detection rule, it proposes zero rules instead of a fake one. Every rule this system has ever produced is marked 'not deployed' and 'pending human review' — there's no code path that lets that be bypassed. I'd rather show you a system that's honest about its gaps than one that looks impressive and isn't."

## Slide 14 — Contributions / Limitations / Future Work
60s. "To be clear about what I'm claiming: none of the individual pieces here — Nmap, ZAP, an LLM writing a detection rule — are new on their own. What I think is worth discussing is the combination: keeping evidence traceable across tools, keeping the AI's proposals separate from what's actually authorized, and having a detection pipeline that can say 'no, not enough telemetry' instead of always producing an answer. And to be honest about the limits: this only ran locally, on Windows, against one test target, with no production authentication, no comparative study against other platforms yet, and validation that only goes as far as 'the rule's syntax is well-formed,' not 'the rule actually works.' Those are the questions I want feedback on today."

## Closing (~30 seconds)

> "The bigger idea I want to leave you with: AI can genuinely help with security reasoning — pulling together context, drafting a rule, explaining a finding — but the actual authorization and execution should stay under deterministic, testable control, not the model's own judgment. Evidence should stay traceable back to where it came from. And a human should still be the one who signs off before anything gets deployed. That's the design ThreatTrace is exploring, and I'd like your feedback on where it's strong and where it still needs work."

## Delivery Notes

- Don't read slide bullets verbatim during Slides 6-9 (the workflow slides) — point at the diagram and narrate.
- Slide 12's table: read 3-4 rows aloud, let the audience read the rest.
- If asked a question mid-slide, it's fine to say "let me get to that in a couple slides" and continue — the flow (especially Slides 9→10→13) is intentional.
- Keep the live demo (if performed) between Slides 11 and 12, or as its own dedicated block after Slide 14 — whichever fits the room's format better; both work with this note structure.
