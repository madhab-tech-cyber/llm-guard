import unittest
from policy_engine.rate_limit import RateLimiter


class RateLimitTests(unittest.TestCase):
    def test_limit_reset_and_capacity(self):
        q = RateLimiter(limit=2, window_seconds=10, max_keys=1)
        self.assertTrue(q.allow("caller-a", now=0))
        self.assertTrue(q.allow("caller-a", now=1))
        self.assertFalse(q.allow("caller-a", now=2))
        self.assertFalse(q.allow("caller-b", now=2))
        self.assertTrue(q.allow("caller-b", now=11))
        self.assertEqual(len(q._state), 1)

    def test_invalid_keys_and_clock_regression_fail_closed(self):
        q = RateLimiter(limit=1, window_seconds=10)
        self.assertFalse(q.allow("private@example.com", now=1))
        self.assertTrue(q.allow("caller", now=5))
        self.assertFalse(q.allow("caller", now=4))
        self.assertFalse(q.allow("caller", now=float("nan")))
