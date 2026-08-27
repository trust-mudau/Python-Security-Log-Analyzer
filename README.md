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


