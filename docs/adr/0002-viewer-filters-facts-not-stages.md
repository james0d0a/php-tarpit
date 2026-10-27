# Viewer filters on logged facts and does not classify stages

The viewer surfaces attack sessions using only facts the sensor logs: request count, method, status, target text, src IP, time range, whether a body was sent, and first sighting. It does not group requests into exploit chains or label stages. Recognising stages belongs to persona matchers. Those are not built yet, and a second rule set in the viewer would drift from them. Exploit-chain and stage views wait until the sensor writes the matched stage into `requests.jsonl`.

## Considered Options

- **Viewer carries its own stage rules**: rejected because it duplicates matcher logic and the two would diverge.
- **Build sensor matchers before the viewer**: rejected because it blocks review on an unbuilt sensor feature.
