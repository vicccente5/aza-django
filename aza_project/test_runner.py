from django.core.management.base import CommandError
from django.db import connections
from django.test.runner import DiscoverRunner


class SQLiteTestRunner(DiscoverRunner):
    def _exigir_sqlite(self):
        if any(config["ENGINE"] != "django.db.backends.sqlite3" for config in connections.settings.values()):
            raise CommandError("Las pruebas requieren SQLite. Ejecute python manage.py test en un proceso nuevo.")

    def run_tests(self, test_labels, **kwargs):
        self._exigir_sqlite()
        return super().run_tests(test_labels, **kwargs)

    def setup_databases(self, **kwargs):
        self._exigir_sqlite()
        return super().setup_databases(**kwargs)
