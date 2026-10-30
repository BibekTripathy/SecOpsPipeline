# Secrets scanner detection report

Corpus seed `20261026`. Regenerate with `make redteam`.

| Metric | Value |
|---|---|
| Planted secrets | 56 |
| Detected | 56 |
| **Detection rate** | **100.0%** |
| Look-alike files | 27 |
| False positives | 0 |

## By rule

| Rule | Detected | Planted |
|---|---|---|
| aws-access-key-id | 13 | 13 |
| aws-secret-access-key | 3 | 3 |
| gateway-token | 1 | 1 |
| generic-assigned-secret | 8 | 8 |
| github-token | 12 | 12 |
| google-api-key | 3 | 3 |
| jwt | 3 | 3 |
| private-key | 6 | 6 |
| slack-token | 3 | 3 |
| stripe-secret-key | 4 | 4 |

## What this number means

Every case in the corpus was written against a rule that already exists, so
a high rate means the scanner has not regressed -- not that nothing escapes
it. The corpus earns its keep in two other ways: it caught two real gaps in
the generic-assignment rule (a quoted JSON key, and a keyword with a suffix
such as `SECRET_KEY`), and it fails the build if a rule change
breaks detection or starts firing on look-alikes.

The false positive count is the number to watch. A scanner that cries wolf
gets bypassed, which is worse than no scanner at all.
