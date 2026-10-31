"""Disposable Linux proof of per-thread nice inheritance and restoration."""
import json, os, threading

ready_old = threading.Event()
ready_new = threading.Event()
finish = threading.Event()
observations = {}

def worker(name, ready):
    tid = threading.get_native_id()
    observations[name] = {'tid': tid, 'nice_at_start': os.getpriority(os.PRIO_PROCESS, 0)}
    ready.set()
    if not finish.wait(20):
        raise RuntimeError('test rendezvous expired')
    observations[name]['nice_after_leader_restore'] = os.getpriority(os.PRIO_PROCESS, 0)
    if observations[name]['nice_after_leader_restore'] != 0:
        os.setpriority(os.PRIO_PROCESS, 0, 0)
    observations[name]['nice_after_self_restore'] = os.getpriority(os.PRIO_PROCESS, 0)

leader = threading.get_native_id()
assert leader == os.getpid() and os.getpriority(os.PRIO_PROCESS, 0) == 0
old = threading.Thread(target=worker, args=('old_thread', ready_old))
old.start()
assert ready_old.wait(10)
try:
    os.setpriority(os.PRIO_PROCESS, 0, -5)
    new = threading.Thread(target=worker, args=('new_thread', ready_new))
    new.start()
    assert ready_new.wait(10)
finally:
    os.setpriority(os.PRIO_PROCESS, 0, 0)
    finish.set()
old.join(10); new.join(10)
assert not old.is_alive() and not new.is_alive()
assert observations['old_thread']['nice_at_start'] == 0
assert observations['old_thread']['nice_after_leader_restore'] == 0
assert observations['new_thread']['nice_at_start'] == -5
assert observations['new_thread']['nice_after_leader_restore'] == -5
assert observations['new_thread']['nice_after_self_restore'] == 0
assert os.getpriority(os.PRIO_PROCESS, 0) == 0
print(json.dumps({'result': 'PASS', 'observations': observations}, sort_keys=True))
