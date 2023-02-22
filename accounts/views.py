from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .forms import UserRegistrationForm
from django.contrib import messages
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required


def login_user(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        try:
            user = authenticate(username=User.objects.get(email=username), password=password)
        except:

            user = authenticate(username=username, password=password)

        if user is not None:
            login(request, user)
            redirect_url = request.GET.get("next", "home")
            return redirect(redirect_url)
        else:
            messages.error(
                request,
                "Username Or Password is incorrect!",
                extra_tags="alert alert-warning alert-dismissible fade show",
            )

    return render(request, "accounts/login.html")


def logout_user(request):
    logout(request)
    return redirect("home")


def create_user(request):
    if request.method == "POST":
        check1 = False
        check2 = False
        check3 = False
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]
            password1 = form.cleaned_data["password1"]
            password2 = form.cleaned_data["password2"]
            email = form.cleaned_data["email"]

            if password1 != password2:
                check1 = True
                messages.error(
                    request,
                    "Password did not match!",
                    extra_tags="alert alert-warning alert-dismissible fade show",
                )
            if User.objects.filter(username=username).exists():
                check2 = True
                messages.error(
                    request,
                    "Username already exists!",
                    extra_tags="alert alert-warning alert-dismissible fade show",
                )
            if User.objects.filter(email=email).exists():
                check3 = True
                messages.error(
                    request,
                    "Email already registered!",
                    extra_tags="alert alert-warning alert-dismissible fade show",
                )

            if check1 or check2 or check3:
                messages.error(
                    request,
                    "Registration Failed!",
                    extra_tags="alert alert-warning alert-dismissible fade show",
                )
                return redirect("accounts:register")
            else:
                user = User.objects.create_user(
                    username=username, password=password1, email=email
                )
                messages.success(
                    request,
                    f"Thanks for registering {user.username}.",
                    extra_tags="alert alert-success alert-dismissible fade show",
                )
                return redirect("accounts:login")
    else:
        form = UserRegistrationForm()
    return render(request, "accounts/register.html", {"form": form})


def change_pass(request):
    if request.user.is_anonymous:
        messages.error(
            request,
            "You need to login",
            extra_tags="alert alert-warning alert-dismissible fade show",
        )

    if request.method == "POST":
        new_pass = request.POST.get("new_pass")
        user = User.objects.get(username=request.user)
        user.set_password(new_pass)
        user.save()
        messages.success(request,"Your password is changed",extra_tags="alert alert-success")
    context = {}
    return render(request, "accounts/set_pass.html", context)


def profile(request):
    return render(request, "accounts/profile.html")
