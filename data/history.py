
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
from app1.models import Issue, StatusHistory

CSV_FILE = os.path.join(
    os.path.dirname(__file__), "status_history_table.csv"
)

created = 0
skipped = 0
errors = 0

with open(CSV_FILE, "r", newline="", encoding="utf-8-sig") as file:
    reader = csv.DictReader(file)

    required = {
        "issue_id", "old_status", "new_status",
        "updated_by", "updated_at"
    }

    if not reader.fieldnames or not required.issubset(reader.fieldnames):
        raise ValueError(
            "CSV headers must be: "
            "issue_id,old_status,new_status,updated_by,updated_at"
        )

    for row in reader:
        try:
            issue_id = int(row["issue_id"].strip())
            username = row["updated_by"].strip()
            old_status = row["old_status"].strip()
            new_status = row["new_status"].strip()

            issue = Issue.objects.get(id=issue_id)
            user = User.objects.get(username=username)

            valid_statuses = dict(Issue.STATUS_CHOICES)

            if new_status not in valid_statuses:
                raise ValueError(f"Invalid new status: {new_status}")

            if old_status and old_status not in valid_statuses:
                raise ValueError(f"Invalid old status: {old_status}")

            updated_at = datetime.strptime(
                row["updated_at"].strip(), "%Y-%m-%d %H:%M:%S"
            )

            if timezone.is_aware(timezone.now()):
                updated_at = timezone.make_aware(
                    updated_at, timezone.get_current_timezone()
                )

            # Avoid importing the same history entry twice
            duplicate = StatusHistory.objects.filter(
                issue=issue,
                old_status=old_status,
                new_status=new_status,
                updated_by=user,
                updated_at=updated_at,
            ).exists()

            if duplicate:
                skipped += 1
                continue

            with transaction.atomic():
                history = StatusHistory.objects.create(
                    issue=issue,
                    old_status=old_status,
                    new_status=new_status,
                    updated_by=user,
                )

                StatusHistory.objects.filter(
                    pk=history.pk
                ).update(updated_at=updated_at)

            created += 1

        except (Issue.DoesNotExist, User.DoesNotExist) as exc:
            print(f"Skipped row: {exc}")
            skipped += 1

        except (ValueError, TypeError) as exc:
            print(f"Invalid row: {exc}")
            errors += 1

print("\nStatus history import finished.")
print(f"Created: {created}")
print(f"Skipped: {skipped}")
print(f"Errors: {errors}")
print(f"Total history records: {StatusHistory.objects.count()}")
