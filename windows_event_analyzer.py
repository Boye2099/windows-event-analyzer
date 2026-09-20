import csv
from datetime import datetime, timedelta
from collections import defaultdict


# ============================================================
# CONFIGURATION
# ============================================================

# Events within this period can be considered part of
# the same activity sequence.
CORRELATION_WINDOW = timedelta(minutes=10)


# Number of authentication failures required before
# we consider the authentication phase suspicious.
FAILED_LOGIN_THRESHOLD = 3


# Windows security event IDs we are interested in.
EVENT_IDS = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4688: "Process Creation",
    4728: "User Added to Global Security Group",
    4729: "User Removed from Global Security Group",
    4732: "User Added to Local Security Group",
    4733: "User Removed from Local Security Group"
}


# Groups that we want to treat as highly privileged
# in this synthetic environment.
PRIVILEGED_GROUPS = {
    "Domain Admins",
    "Administrators",
    "Enterprise Admins"
}


# Processes that deserve additional investigation.
#
# PowerShell is NOT automatically malicious.
# It is simply an important security telemetry source.
INTERESTING_PROCESSES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe"
}


# ============================================================
# LOAD WINDOWS EVENTS
# ============================================================

def load_events(filename):
    """
    Load Windows security events from the CSV file.

    The timestamp is converted into a datetime object,
    and the event ID is converted into an integer.

    All events are then sorted chronologically.
    """

    events = []

    with open(filename, "r", newline="") as file:

        reader = csv.DictReader(file)

        for row in reader:

            # Convert event ID from text to integer.
            row["event_id"] = int(row["event_id"])

            # Convert timestamp from text to datetime.
            row["time"] = datetime.strptime(
                row["time"],
                "%Y-%m-%d %H:%M:%S"
            )

            events.append(row)

    # Security investigations depend heavily on chronology.
    events.sort(
        key=lambda event: event["time"]
    )

    return events


# ============================================================
# EVENT NAME
# ============================================================

def get_event_name(event_id):
    """
    Convert a Windows Event ID into a readable description.
    """

    return EVENT_IDS.get(
        event_id,
        "Unknown Event"
    )


# ============================================================
# GET RECENT EVENTS
# ============================================================

def get_recent_events(events, current_event):
    """
    Return events that happened before the current event
    and within the correlation window.
    """

    recent_events = []

    for event in events:

        # Ignore events that occurred after the current event.
        if event["time"] >= current_event["time"]:
            continue

        difference = (
            current_event["time"] - event["time"]
        )

        if difference <= CORRELATION_WINDOW:

            recent_events.append(event)

    return recent_events


# ============================================================
# COUNT FAILED LOGINS
# ============================================================

def count_recent_failures(events, current_event):
    """
    Count recent Event ID 4625 events.
    """

    count = 0

    for event in get_recent_events(
        events,
        current_event
    ):

        if event["event_id"] == 4625:

            count += 1

    return count


# ============================================================
# FIND RECENT SUCCESSFUL LOGON
# ============================================================

def has_recent_success(events, current_event):
    """
    Determine whether Event ID 4624 occurred recently.
    """

    for event in get_recent_events(
        events,
        current_event
    ):

        if event["event_id"] == 4624:

            return True

    return False


# ============================================================
# FIND RECENT INTERESTING PROCESS
# ============================================================

def has_recent_interesting_process(
    events,
    current_event
):
    """
    Determine whether a process such as PowerShell or
    cmd.exe was created recently.
    """

    for event in get_recent_events(
        events,
        current_event
    ):

        if event["event_id"] != 4688:
            continue

        process = event["process"].lower()

        if process in INTERESTING_PROCESSES:

            return True

    return False


# ============================================================
# CHECK PRIVILEGED GROUP
# ============================================================

def is_privileged_group(group_name):
    """
    Determine whether a group is considered privileged.
    """

    return group_name in PRIVILEGED_GROUPS


# ============================================================
# FIND RECENT PRIVILEGE CHANGE
# ============================================================

def has_recent_privilege_change(
    events,
    current_event
):
    """
    Check whether a recent group membership change
    occurred.
    """

    privilege_events = {
        4728,
        4729,
        4732,
        4733
    }

    for event in get_recent_events(
        events,
        current_event
    ):

        if event["event_id"] in privilege_events:

            return True

    return False


# ============================================================
# BUILD WINDOWS EVENT TIMELINE
# ============================================================

def build_timeline(events):
    """
    Build a chronological timeline of all Windows events.
    """

    timeline = []

    for event in events:

        timeline.append(event)

    return sorted(
        timeline,
        key=lambda event: event["time"]
    )


# ============================================================
# DETECT SUSPICIOUS AUTHENTICATION
# ============================================================

def detect_authentication_patterns(
    events
):
    """
    Detect repeated authentication failures followed
    by a successful logon.
    """

    findings = []

    for event in events:

        if event["event_id"] != 4624:
            continue

        failure_count = count_recent_failures(
            events,
            event
        )

        if failure_count >= FAILED_LOGIN_THRESHOLD:

            findings.append({

                "time": event["time"],

                "type":
                    "Suspicious Authentication Sequence",

                "username":
                    event["username"],

                "source_ip":
                    event["source_ip"],

                "evidence":
                    f"{failure_count} failed logons "
                    "followed by a successful logon"

            })

    return findings


# ============================================================
# DETECT SUSPICIOUS PROCESS CREATION
# ============================================================

def detect_process_activity(events):
    """
    Find interesting process creation events.

    These events are not automatically malicious.
    They are simply useful for investigation.
    """

    findings = []

    for event in events:

        if event["event_id"] != 4688:
            continue

        process = event["process"].lower()

        if process in INTERESTING_PROCESSES:

            findings.append({

                "time": event["time"],

                "type":
                    "Interesting Process Creation",

                "username":
                    event["username"],

                "process":
                    event["process"],

                "parent_process":
                    event["parent_process"]

            })

    return findings


# ============================================================
# DETECT PRIVILEGE CHANGES
# ============================================================

def detect_privilege_changes(events):
    """
    Detect users being added to or removed from
    security-related groups.
    """

    findings = []

    privilege_event_ids = {
        4728,
        4729,
        4732,
        4733
    }

    for event in events:

        if event["event_id"] not in privilege_event_ids:
            continue

        group_name = event["group_name"]

        findings.append({

            "time":
                event["time"],

            "type":
                get_event_name(
                    event["event_id"]
                ),

            "username":
                event["username"],

            "target_account":
                event["target_account"],

            "group_name":
                group_name,

            "privileged":
                is_privileged_group(
                    group_name
                )

        })

    return findings


# ============================================================
# CORRELATE WINDOWS EVENTS
# ============================================================

def correlate_events(events):
    """
    Connect authentication, process creation,
    and privilege changes into larger incidents.
    """

    incidents = []

    for event in events:

        indicators = []
        evidence = []
        score = 0

        # ----------------------------------------------------
        # AUTHENTICATION INDICATOR
        # ----------------------------------------------------

        failure_count = count_recent_failures(
            events,
            event
        )

        if (
            event["event_id"] == 4624
            and failure_count >= FAILED_LOGIN_THRESHOLD
        ):

            indicators.append(
                "Repeated failed logons before success"
            )

            evidence.append(
                f"{failure_count} failed logons "
                "occurred before successful logon"
            )

            score += 30

        # ----------------------------------------------------
        # PROCESS INDICATOR
        # ----------------------------------------------------

        if event["event_id"] == 4688:

            process = event["process"].lower()

            if process in INTERESTING_PROCESSES:

                if has_recent_success(
                    events,
                    event
                ):

                    indicators.append(
                        "Interesting process after logon"
                    )

                    evidence.append(
                        f"{event['process']} was created "
                        "after a recent successful logon"
                    )

                    score += 25

        # ----------------------------------------------------
        # PRIVILEGE CHANGE INDICATOR
        # ----------------------------------------------------

        privilege_event_ids = {
            4728,
            4729,
            4732,
            4733
        }

        if event["event_id"] in privilege_event_ids:

            group_name = event["group_name"]

            if is_privileged_group(
                group_name
            ):

                indicators.append(
                    "Privileged group membership change"
                )

                evidence.append(
                    f"Account {event['target_account']} "
                    f"was involved with "
                    f"{group_name}"
                )

                score += 40

        # ----------------------------------------------------
        # MULTI-STAGE CORRELATION
        # ----------------------------------------------------

        if (
            event["event_id"] in {
                4728,
                4729,
                4732,
                4733
            }
            and has_recent_success(
                events,
                event
            )
        ):

            indicators.append(
                "Privilege change after recent logon"
            )

            evidence.append(
                "A group membership change occurred "
                "after a recent successful logon"
            )

            score += 25

        # ----------------------------------------------------
        # PROCESS + PRIVILEGE CORRELATION
        # ----------------------------------------------------

        if (
            event["event_id"] in {
                4728,
                4729,
                4732,
                4733
            }
            and has_recent_interesting_process(
                events,
                event
            )
        ):

            indicators.append(
                "Privilege change after interesting process"
            )

            evidence.append(
                "A group membership change occurred "
                "after recent process activity"
            )

            score += 30

        # ----------------------------------------------------
        # ONLY CREATE AN INCIDENT IF MULTIPLE
        # INDICATORS ARE CONNECTED.
        # ----------------------------------------------------

        if len(indicators) >= 2:

            if score >= 80:

                severity = "HIGH"

            elif score >= 50:

                severity = "MEDIUM"

            else:

                severity = "LOW"

            incidents.append({

                "time":
                    event["time"],

                "event_id":
                    event["event_id"],

                "event_name":
                    get_event_name(
                        event["event_id"]
                    ),

                "username":
                    event["username"],

                "source_ip":
                    event["source_ip"],

                "target_account":
                    event["target_account"],

                "group_name":
                    event["group_name"],

                "score":
                    score,

                "severity":
                    severity,

                "indicators":
                    indicators,

                "evidence":
                    evidence

            })

    return incidents


# ============================================================
# PRINT WINDOWS EVENT TIMELINE
# ============================================================

def print_timeline(events):

    print("\n" + "=" * 75)
    print("WINDOWS EVENT TIMELINE")
    print("=" * 75)

    for event in events:

        event_name = get_event_name(
            event["event_id"]
        )

        print(
            f"{event['time']} | "
            f"{event['event_id']} | "
            f"{event_name} | "
            f"User: {event['username']}"
        )

        if event["source_ip"]:

            print(
                f"    Source IP: "
                f"{event['source_ip']}"
            )

        if event["target_account"]:

            print(
                f"    Target Account: "
                f"{event['target_account']}"
            )

        if event["group_name"]:

            print(
                f"    Group: "
                f"{event['group_name']}"
            )

        if event["process"]:

            print(
                f"    Process: "
                f"{event['process']}"
            )

        if event["parent_process"]:

            print(
                f"    Parent Process: "
                f"{event['parent_process']}"
            )


# ============================================================
# PRINT INCIDENTS
# ============================================================

def print_incidents(incidents):

    print("\n" + "=" * 75)
    print("WINDOWS SECURITY INCIDENTS")
    print("=" * 75)

    if not incidents:

        print(
            "No correlated Windows security incidents detected."
        )

        return

    for incident in incidents:

        print("\n" + "-" * 75)

        print(
            "Time:",
            incident["time"]
        )

        print(
            "Event:",
            incident["event_name"]
        )

        print(
            "Event ID:",
            incident["event_id"]
        )

        print(
            "Username:",
            incident["username"]
        )

        if incident["source_ip"]:

            print(
                "Source IP:",
                incident["source_ip"]
            )

        if incident["target_account"]:

            print(
                "Target Account:",
                incident["target_account"]
            )

        if incident["group_name"]:

            print(
                "Group:",
                incident["group_name"]
            )

        print(
            "Score:",
            incident["score"]
        )

        print(
            "Severity:",
            incident["severity"]
        )

        print("Indicators:")

        for indicator in incident["indicators"]:

            print(
                " -",
                indicator
            )

        print("Evidence:")

        for evidence in incident["evidence"]:

            print(
                " -",
                evidence
            )


# ============================================================
# PRINT SUMMARY
# ============================================================

def print_summary(incidents):

    print("\n" + "=" * 75)
    print("INVESTIGATION SUMMARY")
    print("=" * 75)

    total = len(incidents)

    high = sum(
        1
        for incident in incidents
        if incident["severity"] == "HIGH"
    )

    medium = sum(
        1
        for incident in incidents
        if incident["severity"] == "MEDIUM"
    )

    low = sum(
        1
        for incident in incidents
        if incident["severity"] == "LOW"
    )

    print(
        "Total incidents:",
        total
    )

    print(
        "High severity:",
        high
    )

    print(
        "Medium severity:",
        medium
    )

    print(
        "Low severity:",
        low
    )


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    filename = "windows_events.csv"

    # Load Windows events.
    events = load_events(filename)

    print(
        "Loaded",
        len(events),
        "Windows security events."
    )

    # Detect authentication patterns.
    authentication_findings = (
        detect_authentication_patterns(
            events
        )
    )

    # Detect interesting process creation.
    process_findings = (
        detect_process_activity(
            events
        )
    )

    # Detect account/group changes.
    privilege_findings = (
        detect_privilege_changes(
            events
        )
    )

    # Correlate the different event types.
    incidents = correlate_events(
        events
    )

    # Print the complete Windows timeline.
    print_timeline(events)

    # Print individual categories of findings.
    print("\n" + "=" * 75)
    print("AUTHENTICATION FINDINGS")
    print("=" * 75)

    for finding in authentication_findings:

        print(
            finding
        )

    print("\n" + "=" * 75)
    print("PROCESS FINDINGS")
    print("=" * 75)

    for finding in process_findings:

        print(
            finding
        )

    print("\n" + "=" * 75)
    print("PRIVILEGE CHANGE FINDINGS")
    print("=" * 75)

    for finding in privilege_findings:

        print(
            finding
        )

    # Print the final correlated incidents.
    print_incidents(
        incidents
    )

    # Print summary.
    print_summary(
        incidents
    )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
