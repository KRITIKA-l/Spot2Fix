
import csv
import os
import sys
import django

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "project1.settings")
django.setup()

from django.contrib.auth.models import User
from app1.models import Profile

CSV_FILE = os.path.join(os.path.dirname(__file__), "users.csv")

created_users = 0
created_profiles = 0
skipped_users = 0

with open(CSV_FILE, "r", newline="", encoding="utf-8-sig") as file:
    reader = csv.DictReader(file)

    required_columns = {
        "username", "email", "first_name",
        "last_name", "role", "phone"
    }

    if not reader.fieldnames or not required_columns.issubset(reader.fieldnames):
        raise ValueError(
            "CSV headers must be: username,email,first_name,"
            "last_name,role,phone"
        )

    for row in reader:
        username = row["username"].strip()
        role = row["role"].strip().lower()

        if role not in ["citizen", "maintenance"]:
            print(f"Skipped {username}: invalid role.")
            skipped_users += 1
            continue

        if not username:
            print("Skipped row: username is empty.")
            skipped_users += 1
            continue

        user, user_created = User.objects.get_or_create(
            username=username,
            defaults={
                "email": row["email"].strip(),
                "first_name": row["first_name"].strip(),
                "last_name": row["last_name"].strip(),
                "is_active": False,
            }
        )

        if user_created:
            # Set an unusable password until a secure demo
            # login/password setup is configured.
            user.set_unusable_password()
            user.save(update_fields=["password"])
            created_users += 1
        else:
            skipped_users += 1

        profile, profile_created = Profile.objects.get_or_create(
            user=user,
            defaults={
                "role": role,
                "phone": row["phone"].strip(),
                "email_verified": False,
            }
        )

        if profile_created:
            created_profiles += 1
        elif user_created:
            # Only update the profile role for a newly created user.
            profile.role = role
            profile.phone = row["phone"].strip()
            profile.email_verified = False
            profile.save()

print("\nImport completed!")
print(f"New users created: {created_users}")
print(f"New profiles created: {created_profiles}")
print(f"Existing/invalid users skipped: {skipped_users}")
print("Existing users and the admin account were not modified.")
