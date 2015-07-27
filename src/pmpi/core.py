import pmpi.database


__database = None


def initialise_database(filename):
    global __database

    if __database is not None:
        raise pmpi.database.Database.InitialisationError("close opened database first")
    __database = pmpi.database.Database(filename)
    __database.initialise_blockchain()


def close_database():
    global __database

    if __database is not None:
        __database.close()
        __database = None
    else:
        raise pmpi.database.Database.InitialisationError("there is no database to close")


def with_database(function):
    global __database

    def wrapper(cls, *args):
        if __database is not None:
            return function(cls, __database, *args)
        else:
            raise pmpi.database.Database.InitialisationError("initialise database first")

    return wrapper


def get_database():
    if __database is not None:
        return __database
    else:
        raise pmpi.database.Database.InitialisationError("initialise database first")
