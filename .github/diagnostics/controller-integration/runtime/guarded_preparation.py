"""LAB-only precomputation of immutable maps before the original ownership lease.

This module has no send, adoption, receipt, Guardian or release authority. The
same Reader is rechecked before its descriptors may be inspected; a caller must
still obtain the original lease, independently revalidate against the Guardian,
and fence a fresh transaction by netlink generation. Never install as a service.
"""
import os
import time

import guarded_nl as nl
import guarded_sources as sources


class Held(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Held(reason)


class PreparedGeneration:
    """Keep fresh frozen maps/FDs tied to one same-process original cache."""

    def __init__(self, cache, *, deadline_ceilings=None):
        self._pid = os.getpid()
        self._cache = cache
        self._closed = False
        self._records = []
        observed = sources.build_expected(cache)
        self._expected = {
            role: dict(observed[role]) for role in ('inbound', 'reverse')
        }
        if deadline_ceilings is not None:
            require(type(deadline_ceilings) is dict and set(deadline_ceilings) == {'inbound', 'reverse'},
                    'EXACT_DEADLINE_CEILING_GROUPS')
            for role in ('inbound', 'reverse'):
                limits = deadline_ceilings[role]
                require(type(limits) is dict and set(limits) == set(self._expected[role])
                        and all(type(v) is int and 0 < v < (1 << 64) for v in limits.values()),
                        'EXACT_DEADLINE_CEILING_ROWS')
                self._expected[role] = {key: min(value, limits[key])
                                        for key, value in self._expected[role].items()}
        self._dnat = dict(observed['dnat'])
        self._cores = frozenset(observed['cores'])
        self._prom = frozenset(observed['prom'])
        self._prepared_ns = time.monotonic_ns()
        try:
            for role in ('inbound', 'reverse'):
                rows = [(key.hex(), deadline) for key, deadline in sorted(self._expected[role].items())]
                self._records.append(nl.make_program(rows))
            self.revalidate(cache)
        except BaseException:
            self.close()
            raise

    def revalidate(self, cache):
        """Discard, rather than refresh, if current original evidence changed."""
        try:
            return self._revalidate(cache)
        except BaseException:
            self.close()
            raise

    def _revalidate(self, cache):
        require(not self._closed and os.getpid() == self._pid and cache is self._cache,
                'LIVE_SAME_PROCESS_ORIGINAL_CACHE_REQUIRED')
        now = time.monotonic_ns()
        require(now >= self._prepared_ns, 'MONOTONIC_CLOCK_REQUIRED')
        current = sources.build_expected(cache, now=now / 1e9)
        require(current['dnat'] == self._dnat and frozenset(current['cores']) == self._cores
                and frozenset(current['prom']) == self._prom, 'PREPARED_TOPOLOGY_CHANGED')
        for role in ('inbound', 'reverse'):
            before = self._expected[role]
            after = current[role]
            require(set(before) == set(after), 'PREPARED_MAP_KEYS_CHANGED')
            require(all(now < deadline <= after[key] for key, deadline in before.items()),
                    'PREPARED_DEADLINE_EXPIRED_OR_EXCEEDS_ORIGINAL')
        return {'source_generation': current['source_generation'],
                'minimum_deadline_ns': min(v for role in self._expected.values() for v in role.values()),
                'production_authority': False}

    def fixture_descriptors(self, cache):
        """Return copies for LAB tests only; this is not permission to send."""
        self.revalidate(cache)
        return tuple(dict(record) for record in self._records)

    def take_same_process_for_emitter(self, cache):
        """Transfer each original FD exactly once; caller becomes its sole closer.

        LAB candidate only. This is not approval to send; the Guardian permit,
        original ownership and generation fences must still be obtained.
        """
        self.revalidate(cache)
        require(len(self._records)==2, 'EXACT_TWO_UNTRANSFERRED_ORIGINAL_FDS')
        records=self._records
        self._records=[]
        self._closed=True
        return records

    def close(self):
        if self._closed:
            return
        self._closed = True
        for record in self._records:
            os.close(record['program_fd'])
            os.close(record['map_fd'])
        self._records.clear()
