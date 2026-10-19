
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
from app1.models import Issue

CSV_FILE = os.path.join(os.path.dirname(__file__), "issues.csv")

VALID_CATEGORIES = dict(Issue.CATEGORY_CHOICES)
VALID_PRIORITIES = dict(Issue.PRIORITY_CHOICES)
VALID_STATUSES = dict(Issue.STATUS_CHOICES)

created = 0
skipped = 0
errors = 0

@transaction.atomic
def import_issues():
    global created, skipped, errors

    with open(CSV_FILE, "r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        required = {
            "username", "title", "description", "category",
            "latitude", "longitude", "priority", "status", "created_at"
        }

        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError("The CSV headers do not match issues.csv.")

        for row in reader:
            username = row["username"].strip()

            try:
                user = User.objects.get(username=username)

                # Only attach demo reports to citizen accounts.
                if not hasattr(user, "profile") or user.profile.role != "citizen":
                    print(f"Skipped row: {username} is not a citizen.")
                    skipped += 1
                    continue

                category = row["category"].strip()
                priority = row["priority"].strip()
                status = row["status"].strip()

                if category not in VALID_CATEGORIES:
                    raise ValueError(f"Invalid category: {category}")

                if priority not in VALID_PRIORITIES:
                    raise ValueError(f"Invalid priority: {priority}")

                if status not in VALID_STATUSES:
                    raise ValueError(f"Invalid status: {status}")

                latitude = float(row["latitude"]) if row["latitude"].strip() else None
                longitude = float(row["longitude"]) if row["longitude"].strip() else None

                created_at = datetime.strptime(
                    row["created_at"].strip(), "%Y-%m-%d %H:%M:%S"
                )

                if timezone.is_aware(timezone.now()):
                    created_at = timezone.make_aware(
                        created_at, timezone.get_current_timezone()
                    )

                # Avoid duplicates when this script is run again.
                title = row["title"].strip()
                if Issue.objects.filter(
                    user=user, title=title
                ).exists():
                    skipped += 1
                    continue

                issue = Issue.objects.create(
                    user=user,
                    title=title,
                    description=row["description"].strip(),
                    category=category,
                    latitude=latitude,
                    longitude=longitude,
                    priority=priority,
                    status=status,
                )

                # created_at uses auto_now_add, so set the CSV timestamp
                # explicitly after creation.
                Issue.objects.filter(pk=issue.pk).update(
                    created_at=created_at
                )

                created += 1

            except User.DoesNotExist:
                print(f"Skipped: user '{username}' does not exist.")
                skipped += 1
            except (ValueError, TypeError) as exc:
                print(f"Error for '{username}': {exc}")
                errors += 1

import_issues()

print("\nIssue import finished.")
print(f"Created: {created}")
print(f"Skipped: {skipped}")
print(f"Errors: {errors}")
print(f"Total issues currently in database: {Issue.objects.count()}")
