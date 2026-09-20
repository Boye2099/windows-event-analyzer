# Windows Event Analyzer

A small Python security project for analyzing Windows security events and finding activity that may need investigation.

The project works with synthetic Windows event logs and looks at events such as successful and failed logons, process creation, and changes to security groups.

## What it does

* Analyzes Windows Event IDs such as 4624, 4625, 4688, 4728, 4729, 4732 and 4733
* Detects repeated failed logons followed by a successful login
* Identifies interesting process activity such as PowerShell
* Detects security group membership changes
* Correlates related events within a time window
* Produces a simple severity score and investigation summary
* Builds a timeline of Windows activity

## Example

The detector can identify a sequence like:

```text
Failed logons
      ↓
Successful logon
      ↓
PowerShell starts
      ↓
User added to a privileged group
```

This doesn't automatically mean an attack happened. It simply highlights the activity so it can be investigated.

## Technologies

* Python
* CSV
* Windows Security Event IDs
* Basic detection and event correlation

## Files

```text
windows-event-analyzer/
├── windows_event_analyzer.py
├── windows_events.csv
├── README.md
└── requirements.txt
```

## Running the project

Make sure Python is installed, then run:

```bash
python windows_event_analyzer.py
```

The project uses Python's standard library, so no external packages are required.

## Note

The logs included in this project are synthetic and created for learning purposes. They are not collected from a real Windows environment.

## What I learned

This project helped me understand how Windows Event IDs can be used to investigate authentication, process activity and privilege changes, and how connecting different events can provide more context than looking at individual events on their own.
