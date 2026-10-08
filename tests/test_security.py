"""Regression tests for the security fixes, plus a check that shopping and rewards still work.

Run from the repository root:
    python -m unittest discover -s tests -v

Each test runs the app in a temporary directory with a copy of sample_data.txt,
so the repository's own files are never modified.
"""
import importlib.util
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import unittest
import warnings

from flask import Flask
from flask.sessions import SecureCookieSessionInterface
from werkzeug.security import check_password_hash

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADMIN_PASSWORD = "test-admin-password"


class AppTestCase(unittest.TestCase):
    def setUp(self):
        # The app opens one SQLite connection per request; when a request is rejected with a 400
        # partway through, Python closes that connection on garbage collection and warns about it.
        warnings.filterwarnings("ignore", message="unclosed database", category=ResourceWarning)
        self.tmp = tempfile.mkdtemp()
        shutil.copy(os.path.join(REPO, "sample_data.txt"), self.tmp)
        self.old_cwd = os.getcwd()
        os.chdir(self.tmp)
        self.old_env = {k: os.environ.get(k) for k in ("ADMIN_PASSWORD", "ADMIN_USERNAME", "SECRET_KEY")}
        os.environ["ADMIN_PASSWORD"] = ADMIN_PASSWORD
        os.environ.pop("ADMIN_USERNAME", None)
        os.environ.pop("SECRET_KEY", None)
        self.mod = self.load_app()
        self.mod.init_db()
        self.app = self.mod.app
        self.client = self.app.test_client()

    def tearDown(self):
        os.chdir(self.old_cwd)
        shutil.rmtree(self.tmp)
        for k, v in self.old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # ---- helpers ----
    def load_app(self):
        spec = importlib.util.spec_from_file_location("ecommerce_app", os.path.join(REPO, "app.py"))
        mod = importlib.util.module_from_spec(spec)
        sys.modules["ecommerce_app"] = mod  # lets Flask find the templates next to app.py
        spec.loader.exec_module(mod)
        return mod

    def token(self, client, path="/"):
        html = client.get(path).get_data(as_text=True)
        match = re.search(r'name="csrf_token" value="([0-9a-f]+)"', html)
        self.assertIsNotNone(match, f"no CSRF token on {path}")
        return match.group(1)

    def register(self, client, username, password, name, **extra):
        data = {"register": "1", "username": username, "password": password, "name": name,
                "csrf_token": self.token(client)}
        data.update(extra)
        return client.post("/", data=data)

    def login(self, client, username, password):
        return client.post("/", data={"login": "1", "username": username, "password": password,
                                      "csrf_token": self.token(client)})

    def db(self, sql, args=()):
        conn = sqlite3.connect("database.db")
        try:
            return conn.execute(sql, args).fetchall()
        finally:
            conn.close()

    def admin_client(self):
        client = self.app.test_client()
        self.assertEqual(self.login(client, "admin", ADMIN_PASSWORD).status_code, 302)
        return client


class TestAuthentication(AppTestCase):
    def test_public_registration_cannot_create_an_admin(self):
        self.register(self.client, "mallory", "pw", "Mallory", user_type="Admin")
        self.assertEqual(self.db("SELECT UserType FROM Users WHERE Username = 'mallory'"), [("Customer",)])
        self.login(self.client, "mallory", "pw")
        response = self.client.get("/customers")
        self.assertEqual(response.status_code, 302, "a self-registered user reached an admin page")

    def test_admin_comes_from_the_environment(self):
        client = self.admin_client()
        self.assertEqual(client.get("/products").status_code, 200)
        self.assertEqual(self.db("SELECT COUNT(*) FROM Users WHERE UserType = 'Admin'"), [(1,)])

    def test_no_default_admin_without_environment(self):
        os.environ.pop("ADMIN_PASSWORD")
        self.mod.init_db()
        self.assertEqual(self.db("SELECT COUNT(*) FROM Users WHERE UserType = 'Admin'"), [(0,)])
        self.assertEqual(self.login(self.client, "admin", "admin123").status_code, 200)  # stays on login page

    def test_login_accepts_right_password_and_rejects_wrong_one(self):
        self.register(self.client, "alice", "correct horse", "Alice")
        self.assertIn("Invalid credentials", self.login(self.client, "alice", "wrong").get_data(as_text=True))
        response = self.login(self.client, "alice", "correct horse")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/shop"))


class TestSessions(AppTestCase):
    def test_secret_key_is_not_the_old_hardcoded_value(self):
        self.assertNotEqual(self.app.secret_key, "COP4710")
        self.assertGreaterEqual(len(self.app.secret_key), 32)

    def test_secret_key_can_come_from_the_environment(self):
        os.environ["SECRET_KEY"] = "a" * 64
        self.assertEqual(self.load_app().app.secret_key, "a" * 64)

    def test_cookie_forged_with_the_old_key_is_rejected(self):
        old = Flask("old")
        old.secret_key = "COP4710"
        forged = SecureCookieSessionInterface().get_signing_serializer(old).dumps(
            {"uid": 1, "user_type": "Admin", "cid": None})
        client = self.app.test_client()
        client.set_cookie("session", forged)
        self.assertEqual(client.get("/products").status_code, 302)

    def test_session_cookie_is_samesite_lax(self):
        self.assertEqual(self.app.config["SESSION_COOKIE_SAMESITE"], "Lax")


class TestPasswordStorage(AppTestCase):
    def test_passwords_are_hashed_in_database_and_data_file(self):
        self.register(self.client, "bob", "s3cret-pass", "Bob")
        (stored,) = self.db("SELECT Password FROM Users WHERE Username = 'bob'")[0]
        self.assertNotEqual(stored, "s3cret-pass")
        self.assertTrue(check_password_hash(stored, "s3cret-pass"))
        with open("sample_data.txt") as f:
            data_file = f.read()
        self.assertNotIn("s3cret-pass", data_file)
        self.assertIn(stored, data_file)

    def test_shipped_data_file_has_no_plaintext_passwords(self):
        with open(os.path.join(REPO, "sample_data.txt")) as f:
            users = f.read().split("USERS", 1)[1]
        self.assertEqual(users.strip(), "")


class TestCsrf(AppTestCase):
    def test_post_without_token_is_rejected(self):
        client = self.admin_client()
        response = client.post("/products", data={"delete": "1", "pid": "1"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.db("SELECT COUNT(*) FROM Product WHERE PID = 1"), [(1,)])

    def test_post_with_token_is_accepted(self):
        client = self.admin_client()
        client.post("/products", data={"delete": "1", "pid": "1", "csrf_token": self.token(client, "/products")})
        self.assertEqual(self.db("SELECT COUNT(*) FROM Product WHERE PID = 1"), [(0,)])

    def test_token_from_another_session_is_rejected(self):
        client = self.admin_client()
        other_token = self.token(self.app.test_client())
        response = client.post("/products", data={"delete": "1", "pid": "1", "csrf_token": other_token})
        self.assertEqual(response.status_code, 400)

    def test_every_post_form_carries_a_token(self):
        for name in os.listdir(os.path.join(REPO, "templates")):
            with open(os.path.join(REPO, "templates", name)) as f:
                html = f.read()
            self.assertEqual(html.count('method="POST"'), html.count("csrf_token()"), name)


class TestInputHandling(AppTestCase):
    def test_registration_requires_a_name(self):
        response = self.register(self.client, "noname", "pw", "")
        self.assertEqual(response.status_code, 200)
        self.assertIn("required", response.get_data(as_text=True))
        self.assertEqual(self.db("SELECT COUNT(*) FROM Users WHERE Username = 'noname'"), [(0,)])

    def test_registration_does_not_take_over_an_existing_customer(self):
        cid, name = self.db("SELECT CID, Name FROM Customer ORDER BY CID LIMIT 1")[0]
        self.register(self.client, "impostor", "pw", name)
        (new_cid,) = self.db("SELECT CID FROM Users WHERE Username = 'impostor'")[0]
        self.assertNotEqual(new_cid, cid)

    def test_shop_survives_a_deleted_customer(self):
        self.register(self.client, "carol", "pw", "Carol")
        self.login(self.client, "carol", "pw")
        conn = sqlite3.connect("database.db"); conn.execute("DELETE FROM Customer WHERE Name = 'Carol'"); conn.commit(); conn.close()
        self.assertEqual(self.client.get("/shop").status_code, 302)

    def test_non_numeric_input_is_a_400_not_a_crash(self):
        client = self.admin_client()
        response = client.post("/products", data={"update": "1", "pid": "1", "price": "abc",
                                                  "csrf_token": self.token(client, "/products")})
        self.assertEqual(response.status_code, 400)


class TestDataFileIntegrity(AppTestCase):
    """The app rebuilds its database from sample_data.txt at every start, so these tests
    restart it (init_db) and check that nothing changes owner or appears from nowhere."""

    def restart(self):
        self.mod.init_db()
        return self.app.test_client()

    def snapshot(self):
        return self.db("""SELECT c.Name, p.Name FROM Buys b JOIN Customer c ON b.CID = c.CID
                          JOIN Product p ON b.PID = p.PID ORDER BY c.Name, p.Name""")

    def test_line_breaks_in_a_name_cannot_inject_an_admin(self):
        from werkzeug.security import generate_password_hash
        injected = "Mallory\nUSERS\nevil," + generate_password_hash("pwned") + ",Admin,NULL"
        response = self.register(self.client, "attacker", "pw", injected)
        self.assertIn("cannot contain", response.get_data(as_text=True))
        client = self.restart()
        self.assertEqual(self.login(client, "evil", "pwned").status_code, 200)  # stays on login page
        self.assertEqual(self.db("SELECT Username FROM Users WHERE UserType = 'Admin'"), [("admin",)])

    def test_admin_text_fields_reject_separator_characters(self):
        client = self.admin_client()
        response = client.post("/customers", data={"add": "1", "name": "Eve\nPRODUCTS\n1,0,Free,Gift",
                                                   "csrf_token": self.token(client, "/customers")})
        self.assertEqual(response.status_code, 400)
        response = client.post("/products", data={"add": "1", "price": "5", "name": "Pens, blue", "category": "Office",
                                                  "csrf_token": self.token(client, "/products")})
        self.assertEqual(response.status_code, 400)

    def test_seed_data_survives_a_restart_unchanged(self):
        before = (self.snapshot(), self.db("SELECT * FROM Product"), self.db("SELECT * FROM Customer"),
                  self.db("SELECT * FROM Vendor"), self.db("SELECT * FROM Supplies"))
        self.mod.sync_to_file()
        self.restart()
        after = (self.snapshot(), self.db("SELECT * FROM Product"), self.db("SELECT * FROM Customer"),
                 self.db("SELECT * FROM Vendor"), self.db("SELECT * FROM Supplies"))
        self.assertEqual(before, after)

    def test_deleting_a_customer_keeps_everyone_elses_purchases_after_restart(self):
        client = self.admin_client()
        cid, name = self.db("SELECT CID, Name FROM Customer WHERE CID = 10")[0]
        client.post("/customers", data={"delete": "1", "cid": str(cid), "csrf_token": self.token(client, "/customers")})
        expected = [row for row in self.snapshot() if row[0] != name]
        self.restart()
        self.assertEqual(self.snapshot(), expected)
        self.assertEqual(self.db("SELECT COUNT(*) FROM Customer WHERE CID = ?", (cid,)), [(0,)])

    def test_new_customer_after_a_restart_starts_with_nothing(self):
        client = self.admin_client()
        last_cid = self.db("SELECT MAX(CID) FROM Customer")[0][0]
        client.post("/customers", data={"delete": "1", "cid": str(last_cid), "csrf_token": self.token(client, "/customers")})
        client = self.restart()
        self.register(client, "frank", "pw", "Frank")
        (cid,) = self.db("SELECT CID FROM Users WHERE Username = 'frank'")[0]
        self.assertEqual(self.db("SELECT COUNT(*) FROM Buys WHERE CID = ?", (cid,)), [(0,)])
        self.assertEqual(self.db("SELECT COUNT(*) FROM Discount WHERE CID = ?", (cid,)), [(0,)])

    def test_account_keeps_its_own_customer_record_after_a_restart(self):
        existing = self.db("SELECT Name FROM Customer ORDER BY CID LIMIT 1")[0][0]
        self.register(self.client, "twin", "pw", existing)
        (cid,) = self.db("SELECT CID FROM Users WHERE Username = 'twin'")[0]
        client = self.restart()
        self.assertEqual(self.db("SELECT CID FROM Users WHERE Username = 'twin'"), [(cid,)])
        self.assertEqual(self.login(client, "twin", "pw").status_code, 302)
        self.assertEqual(client.get("/shop").status_code, 200)

    def test_deleting_a_product_or_vendor_removes_rows_that_point_to_it(self):
        client = self.admin_client()
        pid = self.db("SELECT PID FROM Buys LIMIT 1")[0][0]
        vid = self.db("SELECT VID FROM Supplies LIMIT 1")[0][0]
        client.post("/products", data={"delete": "1", "pid": str(pid), "csrf_token": self.token(client, "/products")})
        client.post("/vendors", data={"delete": "1", "vid": str(vid), "csrf_token": self.token(client, "/vendors")})
        self.assertEqual(self.db("SELECT COUNT(*) FROM Buys WHERE PID = ?", (pid,)), [(0,)])
        self.assertEqual(self.db("SELECT COUNT(*) FROM Supplies WHERE PID = ? OR VID = ?", (pid, vid)), [(0,)])


class TestShoppingStillWorks(AppTestCase):
    def test_purchases_unlock_the_rewards_discount(self):
        self.register(self.client, "dave", "pw", "Dave")
        self.login(self.client, "dave", "pw")
        (cid,) = self.db("SELECT CID FROM Users WHERE Username = 'dave'")[0]
        pids = [row[0] for row in self.db("SELECT PID FROM Product WHERE Category = 'Electronics' ORDER BY PID LIMIT 5")]
        self.assertEqual(len(pids), 5)
        for pid in pids:
            response = self.client.post("/shop", data={"buy": "1", "pid": str(pid), "csrf_token": self.token(self.client, "/shop")})
            self.assertEqual(response.status_code, 200)
        self.assertEqual(self.db("SELECT COUNT(*) FROM Buys WHERE CID = ?", (cid,)), [(5,)])
        self.assertEqual(self.db("SELECT Percentage, Category FROM Discount WHERE CID = ? AND Type = 'Rewards'", (cid,)),
                         [(15.0, "Electronics")])
        self.assertIn("15.0% OFF!", self.client.get("/shop").get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
