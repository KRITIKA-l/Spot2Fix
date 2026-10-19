
import csv
import os
import sys
import django
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "project1.settings")
django.setup()

from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone
from app1.models import Issue, Assignment

CSV_FILE = os.path.join(
    os.path.dirname(__file__), "assignments.csv"
)

created = 0
skipped = 0
errors = 0

with open(CSV_FILE, "r", newline="", encoding="utf-8-sig") as file:
    reader = csv.DictReader(file)

    required = {
        "issue_id", "assigned_to", "department", "assigned_at"
    }

    if not reader.fieldnames or not required.issubset(reader.fieldnames):
        raise ValueError(
            "CSV headers must be: "
            "issue_id,assigned_to,department,assigned_at"
        )

    for row in reader:
        try:
            issue_id = int(row["issue_id"].strip())
            username = row["assigned_to"].strip()
            department = row["department"].strip()

            # Find the existing issue
            issue = Issue.objects.get(id=issue_id)

            # Verify the maintenance user exists and has the correct role
            user = User.objects.get(username=username)

            if user.profile.role != "maintenance":
                print(f"Skipped: {username} is not a maintenance user.")
                skipped += 1
                continue

            # Prevent duplicate assignments to the same maintenance user
            if Assignment.objects.filter(
                issue=issue,
                assigned_to=username,
                department=department,
            ).exists():
                skipped += 1
                continue

            assigned_at = datetime.strptime(
                row["assigned_at"].strip(), "%Y-%m-%d %H:%M:%S"
            )

            if timezone.is_aware(timezone.now()):
                assigned_at = timezone.make_aware(
                    assigned_at, timezone.get_current_timezone()
                )

            with transaction.atomic():
                assignment = Assignment.objects.create(
                    issue=issue,
                    assigned_to=username,
                    department=department,
                )

                # Preserve the timestamp from the CSV
                Assignment.objects.filter(
                    pk=assignment.pk
                ).update(assigned_at=assigned_at)

            created += 1
            print(f"Assigned issue #{issue_id} to {username}")

        except (Issue.DoesNotExist, User.DoesNotExist) as exc:
            print(f"Skipped row: {exc}")
            skipped += 1

        except (ValueError, TypeError) as exc:
            print(f"Invalid row: {exc}")
            errors += 1

print("\nAssignment import finished.")
print(f"Created: {created}")
print(f"Skipped: {skipped}")
print(f"Errors: {errors}")
print(f"Total assignments: {Assignment.objects.count()}")
