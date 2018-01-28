import sqlite3
import db_return


def database_connect(database_file):
    try:
        return db_return.DatabaseConnectionCreated(sqlite3.connect(database_file))
    except sqlite3.Error as e:
        return db_return.DatabaseErrorNotConnected(e)


def store_data(database_name, dev_id, pkey, dev_type):
    db_ret = database_connect(database_name)

    if not db_ret.success():
        return db_ret

    else:
        db = db_ret.connection()
        c = db.cursor()

        # If Devices table does not exist – create it...
        res = c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='Devices';").fetchone()
        if res is None:
            c.execute("CREATE TABLE Devices(device TEXT PRIMARY KEY, device_public_key TEXT, device_type TEXT)")
            db.commit()

        # Now we'll try to add the data to the database
        try:
            c.execute("INSERT INTO Devices VALUES(?,?,?)", (dev_id, pkey, dev_type))
            rv = db_return.DatabaseSuccess()

        except sqlite3.IntegrityError:
            # The integrity error will the thrown if we try to add a duplicate device...
            rv = db_return.DatabaseErrorNonUniqueKey()

        except sqlite3.DatabaseError as e:
            # We'll catch any other database errors here
            rv = db_return.DatabaseErrorGeneric(e)

        finally:
            db.commit()
            db.close()

        return rv


# Here's a relatively simple function which we'll use to return the key that we have stored for the specified device ID
def get_key(database_name, dev_id):
    db_ret = database_connect(database_name)

    if not db_ret.success():
        return db_ret

    else:
        db = db_ret.connection()
        c = db.cursor()
        res = c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='Devices';").fetchone()
        if res is not None:
            c.execute("SELECT device_public_key FROM Devices WHERE device = ?", (dev_id,))
            return c.fetchone()[0]
        else:
            return None
