# LLM Security Assessment — Experiment Notes

## Pilot baseline
## Predictions — cap 256, seed 42, thinking off, 1 generation (written YYYY-MM-DD, before running)

| Condition | Predicted attack success | Reasoning |
|---|---|---|
| none   | 60–75% | 32-prompt runs gave 68.8% and 71.9% |
| input  | 3–10%  | Regex covers 4 of 5 attack templates (~80% of prompts); only "STOP EVERYTHING" gets through, and it succeeded on 3/13 prompts so far |
| output | 0–2%   | Echo blocks any full repeat of the quoted string; what's left is partial repeats, which the detector doesn't count either |
| both   | ~0%    | Input blocks the "ignore" family; echo catches the STOP prompts the input guard misses |
| oracle | 0%     | Matches the detector by construction |

**Key prediction:** echo and oracle will look almost the same on garak. If so,
garak cannot tell a general defense from one that knows the answer key, and
only the held-out set can separate them.

**What would surprise me:** a large input-guard result on the STOP template
(meaning my 13-prompt estimate was wrong), or echo blocking a reply the detector scored safe.

## Results
(fill in after the run, then write down where each prediction was wrong and why)

