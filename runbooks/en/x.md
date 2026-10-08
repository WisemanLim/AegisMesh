# Runbook — extended risk (X) incident
1. **Classify**: use the rule ID to tell X01 (communication), X02 (cascade), X03 (trust abuse), X04 (rogue), X05 (output), X06 (multimodal), X07 (inference) and X08–X10 (operations) apart.
2. **Contain**: put an X04 rogue agent on the quarantine list (`kind=agent`); for an X02 cascade, temporarily downgrade downstream agents on the propagation path to alert_only.
3. **Evidence and review**: export the signed bundle and add the case to the red-team scenarios (X09).
