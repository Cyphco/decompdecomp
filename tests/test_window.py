"""The app's own window (app/window.py): a Chromium-family browser with a profile of its own, so the window is a
process of its own and the app knows when it's closed."""

import stat
import subprocess as sp
import sys
import time

import pytest

from decompnet.app import window


def test_the_browser_is_the_users_chromium_family_one(monkeypatch):
    monkeypatch.delenv("BROWSER", raising=False)
    monkeypatch.setattr(window.hostenv, "runtime", lambda: "native")
    monkeypatch.setattr(window.sys, "platform", "linux")
    monkeypatch.setattr(window.shutil, "which", lambda n: f"/usr/bin/{n}" if n in ("google-chrome", "brave-browser") else None)
    monkeypatch.setattr(window.subprocess, "run", lambda *a, **k: sp.CompletedProcess(a, 0, "brave-browser.desktop\n", ""))
    assert window.browser() == "/usr/bin/brave-browser"  # the default first
    monkeypatch.setattr(window.subprocess, "run", lambda *a, **k: sp.CompletedProcess(a, 0, "firefox.desktop\n", ""))
    monkeypatch.setattr(window.shutil, "which", lambda n: "/usr/bin/google-chrome" if n == "google-chrome" else None)
    assert window.browser() == "/usr/bin/google-chrome"  # Firefox has no app windows: an installed one that does
    monkeypatch.setenv("BROWSER", "true")  # the user (or a test) said how to open pages: a tab
    assert window.browser() is None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX paths and #!/bin/sh stubs: run this one in WSL or Linux")
def test_one_window_and_closing_it_tells_the_app(tmp_path, monkeypatch):
    fake = tmp_path / "browser"
    fake.write_text("#!/bin/sh\nsleep 0.4\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(window, "browser", lambda: str(fake))
    closed = []
    w = window.Window(str(tmp_path / "profile"), lambda: closed.append(1))
    assert w.open("http://127.0.0.1:6464/?k=x") and w.is_open()
    first = w.proc
    assert w.open("http://127.0.0.1:6464/?k=x") and w.proc is first  # asked again: the same window, not a second
    for _ in range(50):
        if closed:
            break
        time.sleep(0.05)
    assert closed == [1] and not w.is_open()


def test_without_an_app_browser_it_is_a_tab(monkeypatch, tmp_path):
    monkeypatch.setattr(window, "browser", lambda: None)
    assert not window.Window(str(tmp_path), lambda: None).open("http://127.0.0.1:6464/")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX paths and #!/bin/sh stubs: run this one in WSL or Linux")
def test_quitting_closes_the_window(tmp_path, monkeypatch):
    fake = tmp_path / "browser"
    fake.write_text("#!/bin/sh\nsleep 30\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(window, "browser", lambda: str(fake))
    closed = []
    w = window.Window(str(tmp_path / "profile"), lambda: closed.append(1))
    assert w.open("http://127.0.0.1:6464/")
    proc = w.proc
    w.close()
    proc.wait(timeout=5)
    time.sleep(0.2)
    assert not w.is_open() and closed == []  # the app closed it: not taken for the user closing it
