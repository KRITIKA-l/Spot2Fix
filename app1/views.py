import hashlib
import logging
import math
import secrets
import smtplib
from collections import deque
from datetime import timedelta
from math import asin, cos, radians, sin, sqrt

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.password_validation import validate_password
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import Case, Count, IntegerField, Q, When
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_POST

from .models import Assignment, EmailOTP, Issue, Profile, StatusHistory

User = get_user_model()
logger = logging.getLogger(__name__)

OTP_EXPIRY = timedelta(minutes=10)
OTP_RESEND_COOLDOWN = timedelta(seconds=60)
OTP_RATE_WINDOW = 60 * 60
OTP_MAX_ATTEMPTS = 5


def generate_email_otp():
    return str(secrets.randbelow(900000) + 100000)


def request_ip(request):
    return request.META.get("REMOTE_ADDR", "unknown")


def otp_rate_key(prefix, value):
    digest = hashlib.sha256(value.encode()).hexdigest()
    return f"spot2fix:{prefix}:{digest}"


def otp_rate_limited(request, email, prefix, limit):
    keys = [
        otp_rate_key(f"{prefix}:ip", request_ip(request)),
        otp_rate_key(f"{prefix}:email", email.lower()),
    ]

    for key in keys:
        if cache.add(key, 1, timeout=OTP_RATE_WINDOW):
            continue
        if cache.incr(key) > limit:
            return True

    return False


# Home page
def home(request):
    stats = Issue.objects.aggregate(
        total=Count("id"),
        in_progress=Count("id", filter=Q(status="in_progress")),
        resolved=Count("id", filter=Q(status="resolved")),
        pending=Count("id", filter=Q(status="submitted")),
    )

    return render(request, "project1/home.html", {"stats": stats})



def redirect_to_dashboard(user):
    try:
        role = user.profile.role
    except Profile.DoesNotExist:
        return redirect("home")

    if role == "admin":
        return redirect("admin_dashboard")

    if role == "maintenance":
        return redirect("maintenance_dashboard")

    return redirect("citizen_dashboard")



@login_required
def my_reports(request):
    try:
        role = request.user.profile.role
    except Profile.DoesNotExist:
        logout(request)
        return redirect("loginuser")

    if role != "citizen":
        return redirect_to_dashboard(request.user)

    reports = Issue.objects.filter(
        user=request.user
    ).order_by("-created_at")

    context = {
        "reports": reports,
        "total_reports": reports.count(),
        "submitted_count": reports.filter(status="submitted").count(),
        "under_review_count": reports.filter(status="under_review").count(),
        "in_progress_count": reports.filter(status="in_progress").count(),
        "resolved_count": reports.filter(status="resolved").count(),
    }

    return render(
        request,
        "project1/my_issue.html",
        context
    )




def signupuser(request):
    if request.user.is_authenticated:
        return redirect_to_dashboard(request.user)

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        email = request.POST.get("email", "").strip()
        phone = request.POST.get("phone", "").strip()
        password1 = request.POST.get("password1", "")
        password2 = request.POST.get("password2", "")

        if not username or not email or not password1 or not password2:
            messages.error(request, "Please fill in all required fields.")
            return render(request, "project1/signupuser.html")

        if otp_rate_limited(request, email, "signup", 5):
            messages.error(
                request,
                "Too many verification requests. Please try again later.",
            )
            return render(request, "project1/signupuser.html")

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return render(request, "project1/signupuser.html")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return render(request, "project1/signupuser.html")

        if User.objects.filter(email__iexact=email).exists():
            messages.error(request, "Email is already registered.")
            return render(request, "project1/signupuser.html")

        if phone and Profile.objects.filter(phone=phone).exists():
            messages.error(request, "Phone number is already registered.")
            return render(request, "project1/signupuser.html")

        try:
            validate_password(password1)
        except ValidationError as error:
            for error_message in error.messages:
                messages.error(request, error_message)
            return render(request, "project1/signupuser.html")

        try:
            with transaction.atomic():
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password1,
                    is_active=False,
                )

                Profile.objects.create(
                    user=user,
                    role="citizen",
                    phone=phone,
                )

                otp = generate_email_otp()
                EmailOTP.objects.create(
                    user=user,
                    code_hash=make_password(otp),
                    expires_at=timezone.now() + OTP_EXPIRY,
                )
                send_mail(
                    "Verify your Spot2Fix email",
                    f"Your Spot2Fix verification code is {otp}. It expires in 10 minutes.",
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                    fail_silently=False,
                )

            request.session["otp_user_id"] = user.pk

            messages.success(request, "A verification code was sent to your email.")
            return redirect("verify_otp")

        except (smtplib.SMTPException, OSError):
            logger.warning("Verification email delivery failed during signup", exc_info=True)
            messages.error(
                request,
                "Could not send the verification email. Check the email settings and try again.",
            )
        except IntegrityError:
            logger.exception("Account creation failed during signup")
            messages.error(request, "Could not create your account. Please try again.")

    return render(request, "project1/signupuser.html")


@require_http_methods(["GET", "POST"])
def verify_otp(request):
    user_id = request.session.get("otp_user_id")

    if not user_id:
        messages.error(request, "Please sign up before verifying OTP.")
        return redirect("signupuser")

    try:
        user = User.objects.get(pk=user_id, is_active=False)
        profile = Profile.objects.get(user=user)

    except (User.DoesNotExist, Profile.DoesNotExist):
        request.session.pop("otp_user_id", None)
        messages.error(request, "Signup session expired. Please sign up again.")
        return redirect("signupuser")

    if request.method == "POST":
        code = request.POST.get("otp", "").strip()

        if not code.isdigit() or len(code) != 6:
            messages.error(request, "Enter the six-digit OTP from your email.")
            return render(request, "project1/verify_otp.html")

        with transaction.atomic():
            otp = EmailOTP.objects.select_for_update().filter(
                user=user,
                used_at__isnull=True,
            ).order_by("-created_at").first()

            if otp is None or otp.expires_at <= timezone.now():
                messages.error(request, "This OTP has expired. Request a new one.")
            elif otp.attempts >= OTP_MAX_ATTEMPTS:
                messages.error(request, "Too many incorrect attempts. Request a new OTP.")
            elif not check_password(code, otp.code_hash):
                otp.attempts += 1
                otp.save(update_fields=["attempts"])
                messages.error(request, "Incorrect OTP.")
            else:
                user.is_active = True
                user.save(update_fields=["is_active"])
                profile.email_verified = True
                profile.save(update_fields=["email_verified"])
                otp.used_at = timezone.now()
                otp.save(update_fields=["used_at"])

                request.session.pop("otp_user_id", None)
                login(request, user)
                messages.success(request, "Email verified successfully. Welcome to Spot2Fix!")
                return redirect_to_dashboard(user)

    return render(request, "project1/verify_otp.html")


@require_POST
def resend_otp(request):
    user_id = request.session.get("otp_user_id")
    if not user_id:
        messages.error(request, "Please sign up before requesting an OTP.")
        return redirect("signupuser")

    user = get_object_or_404(User, pk=user_id, is_active=False)
    if otp_rate_limited(request, user.email, "resend", 5):
        messages.error(request, "Too many OTP requests. Please try again later.")
        return redirect("verify_otp")

    latest_otp = EmailOTP.objects.filter(user=user).order_by("-created_at").first()
    if latest_otp and latest_otp.created_at > timezone.now() - OTP_RESEND_COOLDOWN:
        messages.error(request, "Please wait a minute before requesting another OTP.")
        return redirect("verify_otp")

    otp = generate_email_otp()
    try:
        with transaction.atomic():
            EmailOTP.objects.filter(user=user, used_at__isnull=True).update(
                used_at=timezone.now()
            )
            EmailOTP.objects.create(
                user=user,
                code_hash=make_password(otp),
                expires_at=timezone.now() + OTP_EXPIRY,
            )
            send_mail(
                "Your new Spot2Fix verification code",
                f"Your new Spot2Fix verification code is {otp}. It expires in 10 minutes.",
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
        messages.success(request, "A new verification code was sent to your email.")
    except (smtplib.SMTPException, OSError):
        logger.warning("Verification email delivery failed during resend", exc_info=True)
        messages.error(request, "Could not send a new verification email. Try again later.")
    except IntegrityError:
        logger.exception("OTP resend database operation failed")
        messages.error(request, "Could not create a new verification code. Try again later.")

    return redirect("verify_otp")


def loginuser(request):
    if request.user.is_authenticated:
        if request.user.is_superuser:
            return redirect("admin:index")

        try:
            if request.user.profile.role == "admin":
                return redirect("admin:index")
        except Profile.DoesNotExist:
            pass

        return redirect_to_dashboard(request.user)

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")

        user = authenticate(
            request,
            username=username,
            password=password,
        )

        if user is None:
            inactive_user = User.objects.filter(username=username).first()
            if (
                inactive_user
                and inactive_user.check_password(password)
                and not inactive_user.is_active
            ):
                request.session["otp_user_id"] = inactive_user.pk
                messages.info(
                    request,
                    "Please verify your email address to complete your signup.",
                )
                return redirect("verify_otp")

            messages.error(request, "Invalid username or password.")
            return render(request, "project1/loginuser.html")

        if user.is_superuser:
            messages.info(request, "Please use the admin panel login.")
            return redirect("admin:index")

        try:
            profile = user.profile
        except Profile.DoesNotExist:
            messages.error(request, "User profile not found.")
            return render(request, "project1/loginuser.html")

        if profile.role == "admin":
            messages.info(request, "Please use the admin panel login.")
            return redirect("admin:index")

        if not profile.email_verified:
            messages.error(
                request,
                "Please verify your email address before logging in.",
            )
            return render(request, "project1/loginuser.html")

        login(request, user)
        messages.success(request, "Login successful!")

        return redirect_to_dashboard(user)

    return render(request, "project1/loginuser.html")


def logoutuser(request):
    logout(request)
    messages.success(request, "You have been logged out.")
    return redirect("loginuser")





# Citizen Dashboard

@login_required
def citizen_dashboard(request):
    try:
        role = request.user.profile.role
    except Profile.DoesNotExist:
        logout(request)
        return redirect("loginuser")

    issues = Issue.objects.filter(
        user=request.user
    ).order_by("-created_at")
    status_counts = {
        "submitted": issues.filter(status="submitted").count(),
        "under_review": issues.filter(status="under_review").count(),
        "in_progress": issues.filter(status="in_progress").count(),
        "resolved": issues.filter(status="resolved").count(),
    }

    context = {
        "total_issues": issues.count(),
        "status_counts": status_counts,
        "recent_issues": issues[:5],
    }

    return render(
        request,
        "project1/citizen_dashboard.html",
        context
    )




@login_required
def report_issue(request):
    # Check the user's role
    try:
        role = request.user.profile.role
    except Profile.DoesNotExist:
        logout(request)
        return redirect("loginuser")

    if role != "citizen":
        return redirect_to_dashboard(request.user)

    form_data = {}

    if request.method == "POST":
        title = request.POST.get("title", "").strip()
        description = request.POST.get("description", "").strip()
        category = request.POST.get("category", "").strip()
        priority = request.POST.get("priority", "medium").strip()

        latitude = request.POST.get("latitude", "").strip()
        longitude = request.POST.get("longitude", "").strip()
        photo = request.FILES.get("photo")

        form_data = {
            "title": title,
            "description": description,
            "category": category,
            "priority": priority,
            "latitude": latitude,
            "longitude": longitude,
        }

        errors = []

        # Validate required fields
        if not title:
            errors.append("Please enter an issue title.")
        elif len(title) > 200:
            errors.append("The title cannot exceed 200 characters.")

        if not description:
            errors.append("Please describe the issue.")

        # Validate category and priority against model choices
        valid_categories = dict(Issue.CATEGORY_CHOICES)
        valid_priorities = dict(Issue.PRIORITY_CHOICES)

        if category not in valid_categories:
            errors.append("Please select a valid issue category.")

        if priority not in valid_priorities:
            errors.append("Please select a valid priority.")

        # Validate coordinates
        latitude_value = None
        longitude_value = None

        if bool(latitude) != bool(longitude):
            errors.append("Both latitude and longitude are required together.")

        if latitude and longitude:
            try:
                latitude_value = float(latitude)
                longitude_value = float(longitude)

                if not math.isfinite(latitude_value) or not (-90 <= latitude_value <= 90):
                    errors.append("Invalid latitude value.")

                if not math.isfinite(longitude_value) or not (-180 <= longitude_value <= 180):
                    errors.append("Invalid longitude value.")

            except (ValueError, TypeError):
                errors.append("The location coordinates are invalid.")

        # Basic photo validation
        if photo:
            if not photo.content_type or not photo.content_type.startswith("image/"):
                errors.append("Please upload a valid image.")

            if photo.size > 5 * 1024 * 1024:
                errors.append("The photo must be smaller than 5 MB.")

        if errors:
            return render(
                request,
                "project1/report_issue.html",
                {
                    "form_errors": errors,
                    "form_data": form_data,
                },
            )

        with transaction.atomic():
            issue = Issue.objects.create(
                user=request.user,
                title=title,
                description=description,
                category=category,
                priority=priority,
                photo=photo,
                latitude=latitude_value,
                longitude=longitude_value,
                status="submitted",
            )

            issue.history.create(
                old_status="",
                new_status="submitted",
                updated_by=request.user,
            )

        messages.success(
            request,
            "Your issue has been reported successfully!"
        )

        return redirect("citizen_dashboard")

    return render(
        request,
        "project1/report_issue.html",
        {"form_data": form_data},
    )







def merge_sort_issues(issues):
    """Merge Sort: high priority first, then older reports first."""

    priority_order = {
        "high": 0,
        "medium": 1,
        "low": 2,
    }

    def sort_key(issue):
        return (
            priority_order.get(issue.priority, 3),
            issue.created_at,
            issue.id,
        )

    if len(issues) <= 1:
        return issues

    middle = len(issues) // 2
    left = merge_sort_issues(issues[:middle])
    right = merge_sort_issues(issues[middle:])

    result = []
    i = j = 0

    while i < len(left) and j < len(right):
        if sort_key(left[i]) <= sort_key(right[j]):
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1

    result.extend(left[i:])
    result.extend(right[j:])

    return result


@login_required
def admin_dashboard(request):
    try:
        role = request.user.profile.role
    except Profile.DoesNotExist:
        role = None

    if not request.user.is_superuser and role != "admin":
        return redirect_to_dashboard(request.user)

    all_issues = Issue.objects.select_related("user").all()

    # Statistics
    stats = all_issues.aggregate(
        total=Count("id"),
        pending=Count("id", filter=Q(status="submitted")),
        under_review=Count("id", filter=Q(status="under_review")),
        in_progress=Count("id", filter=Q(status="in_progress")),
        resolved=Count("id", filter=Q(status="resolved")),
        high_priority=Count("id", filter=Q(priority="high")),
    )

    # Search and filters
    query = request.GET.get("q", "").strip()
    selected_status = request.GET.get("status", "").strip()
    selected_priority = request.GET.get("priority", "").strip()
    selected_category = request.GET.get("category", "").strip()

    # Independent sorting controls
    selected_priority_sort = request.GET.get(
        "priority_sort", "high_first"
    ).strip()

    selected_time_sort = request.GET.get(
        "time_sort", "newest"
    ).strip()

    if selected_priority_sort not in ["high_first", "low_first"]:
        selected_priority_sort = "high_first"

    if selected_time_sort not in ["newest", "oldest"]:
        selected_time_sort = "newest"

    valid_statuses = dict(Issue.STATUS_CHOICES)
    valid_priorities = dict(Issue.PRIORITY_CHOICES)
    valid_categories = dict(Issue.CATEGORY_CHOICES)

    issues = all_issues

    if selected_status in valid_statuses:
        issues = issues.filter(status=selected_status)
    else:
        selected_status = ""

    if selected_priority in valid_priorities:
        issues = issues.filter(priority=selected_priority)
    else:
        selected_priority = ""

    if selected_category in valid_categories:
        issues = issues.filter(category=selected_category)
    else:
        selected_category = ""

    if query:
        issues = issues.filter(
            Q(title__icontains=query)
            | Q(description__icontains=query)
            | Q(user__username__icontains=query)
        )

    # Priority and time sorting remain separate controls.
    if selected_priority_sort == "low_first":
        priority_order = Case(
            When(priority="low", then=0),
            When(priority="medium", then=1),
            When(priority="high", then=2),
            default=3,
            output_field=IntegerField(),
        )
    else:
        priority_order = Case(
            When(priority="high", then=0),
            When(priority="medium", then=1),
            When(priority="low", then=2),
            default=3,
            output_field=IntegerField(),
        )

    if selected_time_sort == "oldest":
        time_order = "created_at"
    else:
        time_order = "-created_at"

    issues = issues.annotate(
        priority_order=priority_order
    ).order_by(
        "priority_order",
        time_order,
        "id",
    )

    # Pagination
    paginator = Paginator(issues, 10)
    page_obj = paginator.get_page(request.GET.get("page"))

    maintenance_users = User.objects.filter(
        profile__role="maintenance"
    ).order_by("username")

    context = {
        "total_issues": stats["total"],
        "pending_issues": stats["pending"],
        "under_review_issues": stats["under_review"],
        "in_progress_issues": stats["in_progress"],
        "resolved_issues": stats["resolved"],
        "high_priority_issues": stats["high_priority"],

        "page_obj": page_obj,
        "recent_issues": page_obj.object_list,

        "query": query,
        "selected_status": selected_status,
        "selected_priority": selected_priority,
        "selected_category": selected_category,

        "selected_priority_sort": selected_priority_sort,
        "selected_time_sort": selected_time_sort,

        "status_choices": Issue.STATUS_CHOICES,
        "priority_choices": Issue.PRIORITY_CHOICES,
        "category_choices": Issue.CATEGORY_CHOICES,

        "maintenance_users": maintenance_users,
    }

    return render(
        request,
        "project1/admin_dashboard.html",
        context,
    )







def issue_list(request):
    query = request.GET.get("q", "").strip()

    issues = Issue.objects.all()

    if query:
        issues = issues.filter(
            Q(title__icontains=query)
            | Q(description__icontains=query)
            | Q(category__icontains=query)
            | Q(status__icontains=query)
        )

    context = {
        "issues": issues.order_by("-created_at"),
        "query": query,
    }

    return render(request, "project1/issue_list.html", context)







@login_required
@require_POST
def admin_issue_action(request, issue_id):
    try:
        role = request.user.profile.role
    except Profile.DoesNotExist:
        role = None

    if not request.user.is_superuser and role != "admin":
        return redirect_to_dashboard(request.user)

    issue = get_object_or_404(Issue, id=issue_id)
    action = request.POST.get("action", "").strip()

    if action == "priority":
        new_priority = request.POST.get("priority", "").strip()

        if new_priority not in dict(Issue.PRIORITY_CHOICES):
            messages.error(request, "Please select a valid priority.")
        else:
            issue.priority = new_priority
            issue.save(update_fields=["priority"])
            messages.success(request, "Priority updated successfully.")

    elif action == "status":
        new_status = request.POST.get("status", "").strip()

        if new_status not in dict(Issue.STATUS_CHOICES):
            messages.error(request, "Please select a valid status.")

        elif issue.status == new_status:
            messages.info(request, "The issue already has this status.")

        else:
            old_status = issue.status

            with transaction.atomic():
                issue.status = new_status
                issue.save(update_fields=["status"])

                StatusHistory.objects.create(
                    issue=issue,
                    old_status=old_status,
                    new_status=new_status,
                    updated_by=request.user,
                )

            messages.success(request, "Status updated successfully.")

    elif action == "assign":
        username = request.POST.get("assigned_to", "").strip()
        department = request.POST.get("department", "").strip()

        try:
            maintenance_profile = Profile.objects.select_related(
                "user"
            ).get(
                user__username=username,
                role="maintenance",
            )
        except Profile.DoesNotExist:
            messages.error(
                request,
                "Please select a valid maintenance user.",
            )
        else:
            assigned_username = maintenance_profile.user.username

            if Assignment.objects.filter(
                issue=issue,
                assigned_to=assigned_username,
            ).exists():
                messages.info(
                    request,
                    "This issue is already assigned to that user.",
                )
            else:
                Assignment.objects.create(
                    issue=issue,
                    assigned_to=assigned_username,
                    department=department,
                )
                messages.success(request, "Issue assigned successfully.")

    else:
        messages.error(request, "Invalid action.")

    return redirect(
        request.META.get("HTTP_REFERER", "/admin/dashboard/")
    )



def calculate_distance(lat1, lon1, lat2, lon2):
    """Calculate straight-line distance between two GPS points in km."""

    lat1, lon1, lat2, lon2 = map(
        float, [lat1, lon1, lat2, lon2]
    )

    lat1, lon1, lat2, lon2 = map(
        radians, [lat1, lon1, lat2, lon2]
    )

    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = (
        sin(dlat / 2) ** 2
        + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    )

    a = min(1.0, max(0.0, a))

    return 6371 * 2 * asin(sqrt(a))


def bfs_nearby_assignments(assignments, radius_km=2):
    """
    Arrange assignments using BFS.

    Two issues are connected when their straight-line GPS
    distance is at most radius_km.
    """

    assignments = list(assignments)

    located = []
    unlocated = []

    for assignment in assignments:
        issue = assignment.issue

        if issue.latitude is not None and issue.longitude is not None:
            located.append(assignment)
        else:
            unlocated.append(assignment)

    count = len(located)

    if count == 0:
        return assignments

    # Each issue is a graph node.
    graph = {i: [] for i in range(count)}

    # Create edges between issues within the distance threshold.
    for i in range(count):
        issue_a = located[i].issue

        for j in range(i + 1, count):
            issue_b = located[j].issue

            distance = calculate_distance(
                issue_a.latitude,
                issue_a.longitude,
                issue_b.latitude,
                issue_b.longitude,
            )

            if distance <= radius_km:
                graph[i].append(j)
                graph[j].append(i)

    # Prefer high-priority issues as traversal starting points.
    priority_order = {
        "high": 0,
        "medium": 1,
        "low": 2,
    }

    def start_key(index):
        assignment = located[index]

        return (
            priority_order.get(
                assignment.issue.priority, 3
            ),
            assignment.assigned_at,
            assignment.pk,
        )

    start_order = sorted(range(count), key=start_key)

    visited = set()
    ordered = []

    # Traverse every connected component.
    for start in start_order:
        if start in visited:
            continue

        queue = deque([start])
        visited.add(start)

        while queue:
            current = queue.popleft()
            ordered.append(located[current])

            neighbours = sorted(
                graph[current],
                key=start_key,
            )

            for neighbour in neighbours:
                if neighbour not in visited:
                    visited.add(neighbour)
                    queue.append(neighbour)

    # Issues without coordinates cannot participate in the graph.
    unlocated.sort(key=lambda a: (a.assigned_at, a.pk))

    return ordered + unlocated

@login_required
def maintenance_dashboard(request):
    if not request.user.is_superuser:
        try:
            if request.user.profile.role != "maintenance":
                messages.error(
                    request,
                    "You are not authorized to access this dashboard."
                )
                return redirect("home")
        except Profile.DoesNotExist:
            messages.error(request, "User profile not found.")
            return redirect("home")

    # Only assignments belonging to the logged-in officer.
    base_assignments = Assignment.objects.filter(
        assigned_to=request.user.username
    ).select_related(
        "issue",
        "issue__user",
    )

    issue_ids = list(
        base_assignments.values_list("issue_id", flat=True)
    )

    # Statistics for this officer's assigned issues.
    stats_data = Issue.objects.filter(
        id__in=issue_ids
    ).aggregate(
        total=Count("id"),
        pending=Count("id", filter=Q(status="submitted")),
        under_review=Count(
            "id", filter=Q(status="under_review")
        ),
        in_progress=Count(
            "id", filter=Q(status="in_progress")
        ),
        resolved=Count("id", filter=Q(status="resolved")),
        high_priority=Count(
            "id", filter=Q(priority="high")
        ),
    )

    stats = {
        key: value or 0
        for key, value in stats_data.items()
    }

    # Search and filters.
    search_query = request.GET.get("q", "").strip()
    selected_status = request.GET.get("status", "").strip()
    selected_priority = request.GET.get("priority", "").strip()

    filtered_assignments = base_assignments

    if search_query:
        filtered_assignments = filtered_assignments.filter(
            Q(issue__title__icontains=search_query)
            | Q(issue__description__icontains=search_query)
            | Q(issue__user__username__icontains=search_query)
            | Q(department__icontains=search_query)
        )

    valid_statuses = {
        value for value, label in Issue.STATUS_CHOICES
    }
    valid_priorities = {
        value for value, label in Issue.PRIORITY_CHOICES
    }

    if selected_status in valid_statuses:
        filtered_assignments = filtered_assignments.filter(
            issue__status=selected_status
        )
    else:
        selected_status = ""

    if selected_priority in valid_priorities:
        filtered_assignments = filtered_assignments.filter(
            issue__priority=selected_priority
        )
    else:
        selected_priority = ""

    # BFS ordering applies to the filtered assignments.
    ordered_assignments = bfs_nearby_assignments(
        filtered_assignments.order_by(
            "-assigned_at", "-pk"
        )
    )

    paginator = Paginator(ordered_assignments, 10)
    page_obj = paginator.get_page(request.GET.get("page"))

    context = {
        "stats": stats,
        "page_obj": page_obj,
        "assignments": page_obj.object_list,
        "search_query": search_query,
        "selected_status": selected_status,
        "selected_priority": selected_priority,
        "status_choices": Issue.STATUS_CHOICES,
        "priority_choices": Issue.PRIORITY_CHOICES,
    }

    return render(
        request,
        "project1/maintenance_dashboard.html",
        context,
    )

@login_required
@require_POST
def maintenance_issue_action(request, issue_id):
    try:
        profile = request.user.profile
    except Profile.DoesNotExist:
        messages.error(request, "User profile not found.")
        return redirect("home")

    if profile.role != "maintenance":
        messages.error(
            request,
            "You are not authorized to update this issue."
        )
        return redirect("home")

    assignment = get_object_or_404(
        Assignment.objects.select_related("issue"),
        issue_id=issue_id,
        assigned_to=request.user.username,
    )

    issue = assignment.issue
    new_status = request.POST.get("status", "").strip()

    allowed_statuses = {"in_progress", "resolved"}

    if new_status not in allowed_statuses:
        messages.error(request, "Invalid status selected.")
        return redirect("maintenance_dashboard")

    if issue.status == "resolved":
        messages.error(
            request,
            "This issue has already been resolved."
        )
        return redirect("maintenance_dashboard")

    if (
        new_status == "resolved"
        and issue.status not in {"in_progress", "under_review"}
    ):
        messages.error(
            request,
            "Move the issue to In Progress before resolving it."
        )
        return redirect("maintenance_dashboard")

    if issue.status == new_status:
        messages.info(request, "The issue already has this status.")
        return redirect("maintenance_dashboard")

    with transaction.atomic():
        old_status = issue.status
        issue.status = new_status
        issue.save(update_fields=["status"])

        StatusHistory.objects.create(
            issue=issue,
            old_status=old_status,
            new_status=new_status,
            updated_by=request.user,
        )

    messages.success(
        request,
        f"Issue #{issue.pk} updated successfully."
    )

    return redirect("maintenance_dashboard")



@login_required
def maintenance_recommendations(request):
    try:
        profile = request.user.profile
    except Profile.DoesNotExist:
        messages.error(request, "User profile not found.")
        return redirect("home")

    if profile.role != "maintenance":
        messages.error(request, "Access denied.")
        return redirect("home")

    # Get assignments belonging to the logged-in maintenance officer.
    assignments = list(
        Assignment.objects.filter(
            assigned_to=request.user.username
        ).select_related(
            "issue",
            "issue__user",
        ).order_by("-assigned_at", "-pk")
    )

    # Separate issues that have GPS coordinates from those that do not.
    located = []
    unlocated = []

    for assignment in assignments:
        issue = assignment.issue

        if issue.latitude is not None and issue.longitude is not None:
            located.append(assignment)
        else:
            unlocated.append(assignment)

    count = len(located)

    # Build the graph using a 2 km distance threshold.
    graph = {i: [] for i in range(count)}
    edges = []

    for i in range(count):
        for j in range(i + 1, count):
            issue_a = located[i].issue
            issue_b = located[j].issue

            distance = calculate_distance(
                issue_a.latitude,
                issue_a.longitude,
                issue_b.latitude,
                issue_b.longitude,
            )

            if distance <= 2:
                graph[i].append(j)
                graph[j].append(i)

                edges.append({
                    "source": i,
                    "target": j,
                    "distance": round(distance, 2),
                })

    # Define priority ordering for BFS starting nodes and neighbours.
    priority_order = {
        "high": 0,
        "medium": 1,
        "low": 2,
    }

    def start_key(index):
        assignment = located[index]

        return (
            priority_order.get(
                assignment.issue.priority, 3
            ),
            assignment.assigned_at,
            assignment.pk,
        )

    start_order = sorted(range(count), key=start_key)

    visited = set()
    bfs_order = []
    components = []
    component_number = {}

    # BFS traversal across every connected component.
    for start in start_order:
        if start in visited:
            continue

        queue = deque([start])
        visited.add(start)
        component = []

        while queue:
            current = queue.popleft()

            bfs_order.append(current)
            component.append(current)

            neighbours = sorted(
                graph[current],
                key=start_key,
            )

            for neighbour in neighbours:
                if neighbour not in visited:
                    visited.add(neighbour)
                    queue.append(neighbour)

        group_number = len(components) + 1

        for index in component:
            component_number[index] = group_number

        components.append(component)

    # Arrange graph nodes in a snake layout: four issues per row.
    nodes = []

    columns = 4
    start_x = 110
    start_y = 90
    gap_x = 190
    gap_y = 145

    for position, index in enumerate(bfs_order):
        row = position // columns
        col = position % columns

        # Reverse every alternate row.
        if row % 2 == 1:
            col = columns - 1 - col

        x = start_x + col * gap_x
        y = start_y + row * gap_y

        assignment = located[index]
        issue = assignment.issue

        nodes.append({
            "index": index,
            "x": x,
            "y": y,
            "id": issue.pk,
            "title": issue.title,
            "priority": issue.get_priority_display(),
            "priority_key": issue.priority,
            "status": issue.get_status_display(),
            "category": issue.get_category_display(),
            "component": component_number[index],
            "bfs_position": position + 1,
            "latitude": issue.latitude,
            "longitude": issue.longitude,
        })

    # Map graph indices to node positions.
    node_positions = {
        node["index"]: node
        for node in nodes
    }

    # Add SVG coordinates to the existing GPS graph edges.
    for edge in edges:
        source_node = node_positions[edge["source"]]
        target_node = node_positions[edge["target"]]

        edge["x1"] = source_node["x"]
        edge["y1"] = source_node["y"]
        edge["x2"] = target_node["x"]
        edge["y2"] = target_node["y"]

        edge["source_id"] = source_node["id"]
        edge["target_id"] = target_node["id"]

    # Arrange assignments in BFS order.
    ordered_assignments = [
        located[index]
        for index in bfs_order
    ]

    # Calculate chart dimensions based on the number of nodes.
    total_rows = (len(nodes) + columns - 1) // columns

    chart_width = (
        start_x * 2
        + (columns - 1) * gap_x
    )

    chart_height = (
        start_y * 2
        + max(0, total_rows - 1) * gap_y
    )

    # Send all required data to the template.
    context = {
        "nodes": nodes,
        "edges": edges,
        "components": components,
        "component_count": len(components),
        "located_count": count,
        "unlocated_assignments": unlocated,
        "bfs_assignments": ordered_assignments,
        "total_assignments": len(assignments),
        "chart_width": chart_width,
        "chart_height": chart_height,
    }

    return render(
        request,
        "project1/maintenance_recommendations.html",
        context,
    )
