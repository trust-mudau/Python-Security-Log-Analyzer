# Python Security Log Analyzer

## Objective
Build a Python tool that reads synthetic authentication logs and identifies suspicious patterns such as repeated failed logins and a successful login after multiple failures.

## Skills Demonstrated
- Python
- Log parsing
- Detection logic
- Basic SOC analysis
- Alert generation
- JSON reporting

## Quick Start
```bash
python analyzer.py sample_logs/auth.log
```

## Detection Cases
- More than 5 failed logins from one IP
- Multiple usernames targeted by one IP
- Successful login after repeated failures
- Repeated authentication failures against one user

## Portfolio Goal
Do not only upload code. Explain why each rule exists, show example output, document false positives, and describe how you would improve the rule in a production SOC.
