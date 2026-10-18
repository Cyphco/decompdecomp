"""Stopping helpers explicitly must win over an overlapping app shutdown's resume snapshot."""

import threading
from contextlib import contextmanager
from types import SimpleNamespace

from decompnet.app.agents import Manager, Session


def manager():
    @contextmanager
    def transaction():
        yield SimpleNamespace(execute=lambda *_: None)

    m = Manager.__new__(Manager)
    m._lock = threading.Lock()
    m.net = SimpleNamespace(store=SimpleNamespace(tx=transaction))
    m.sessions = {str(i): Session(str(i), "opencode", str(i), "demo", str(i), {}) for i in range(2)}
    return m


def test_explicit_stop_is_serialized_with_the_quit_resume_snapshot():
    m = manager()
    saving_quit, release_quit, user_stopped = (threading.Event() for _ in range(3))
    saved = []

    def persist(running):
        if threading.current_thread().name == "quit":
            saving_quit.set()
            assert release_quit.wait(3)
        saved.append(running)

    def stop_user_helpers():
        for sid in m.sessions:
            m.stop(sid)
        user_stopped.set()

    m.persist = persist
    quitting = threading.Thread(target=m.stop, name="quit")
    quitting.start()
    assert saving_quit.wait(3)
    stopping = threading.Thread(target=stop_user_helpers)
    stopping.start()
    try:
        assert not user_stopped.wait(.1), "the explicit stop must wait for the pending quit snapshot"
    finally:
        release_quit.set()
        quitting.join(3)
        stopping.join(3)
    assert not quitting.is_alive() and not stopping.is_alive()
    assert saved[-1] == []


def test_quit_preserves_running_helpers_but_not_explicitly_stopped_helpers():
    m = manager()
    saved = []
    m.persist = saved.append
    m.stop()
    assert len(saved[-1]) == 2
    m = manager()
    m.persist = saved.append
    for sid in m.sessions:
        m.stop(sid)
    m.stop()
    assert saved[-1] == []


def test_start_saves_its_resume_state_before_releasing_the_lifecycle_lock(monkeypatch, tmp_path):
    m = manager()
    m.sessions = {}
    m.log_dir = tmp_path
    m._prepare = lambda slug: None
    monkeypatch.setattr(threading.Thread, "start", lambda self: None)
    saved = []

    def persist(running):
        assert m._lock.locked(), "shutdown must not stop a new helper before its resume state is saved"
        saved.append(running)

    m.persist = persist
    assert len(m.start("opencode", "demo")) == 1
    m.stop()
    assert len(saved[-1]) == 1


def test_finishing_helper_cannot_erase_the_quit_snapshot(tmp_path):
    m = manager()
    m.home, m.assignments, m._prep = tmp_path, {}, {}
    m.net.local_agent = lambda name: (SimpleNamespace(id=1), "token")
    m.net.store.one = lambda *args: None
    m.net.links = {}
    m._left = lambda slug: 0
    terminal, release, quit_done = (threading.Event() for _ in range(3))

    class PausedStop(threading.Event):
        def set(self):
            super().set()
            if threading.current_thread().name == "finishing":
                terminal.set()
                assert release.wait(3)

    s = m.sessions["0"]
    s.stop = PausedStop()
    saved = []
    m.persist = saved.append
    finishing = threading.Thread(target=m._run, args=(s,), name="finishing")

    def quit_app():
        m.stop()
        quit_done.set()

    quitting = threading.Thread(target=quit_app)
    finishing.start()
    assert terminal.wait(3)
    quitting.start()
    try:
        assert not quit_done.wait(.1), "quit must wait for completion to save its state"
    finally:
        release.set()
        finishing.join(3)
        quitting.join(3)
    assert not finishing.is_alive() and not quitting.is_alive()
    assert len(saved[-1]) == 1, "the other helper must still resume after quit"
