"""Build-time smoke for the PostgreSQL URLs accepted by the migration image.

Creating an engine loads the DBAPI without opening a database connection.
"""

from sqlalchemy import create_engine


def main() -> None:
    for scheme in ("postgresql", "postgresql+psycopg", "postgresql+psycopg2"):
        engine = create_engine(f"{scheme}://marty:marty@localhost/marty")
        engine.dispose()
        print(f"Migration database driver loaded: {scheme}")


if __name__ == "__main__":
    main()
