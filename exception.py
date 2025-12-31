class MissingColumnError(Exception):
    '''This Exception Class is used to raise error when uploaded
       file doesnt contains any column
    '''
    def __init__(self, column_name,file):
        self.column_name = str(column_name)[1:-1]
        self.file = file

    def __str__(self):
        return f"'{self.column_name}' Columns missing in '{self.file}' dataset."

class DataNotAvailable(Exception):
    '''This Exception Class is used to raise error when Selected order has no records.
    '''
    def __init__(self):
        self.msg = 'Data Not Found.'

    def __str__(self):
        return f"Selected order has no data."
    


class FileNotAvailable(Exception):
    'File Not Available.'
    def __init__(self):
        self.msg = 'File Not Available in google drive.'
    def __str__(self):
        return self.msg

class TableNotExist(Exception):
    'Table Not Found.'
    def __init__(self):
        self.msg = 'Table Not Found.Please Check In Database.'
    def __str__(self):
        return self.msg

class FolderNotAvailable(Exception):
    'Folder Not Available.'
    def __init__(self):
        self.msg = 'In Google Drive Folder Not Available.'
    def __str__(self):
        return self.msg


class EmailExist(Exception):
    'Email already exist.'
    def __init__(self):
        self.msg = 'Email already exist.'
    def __str__(self):
        return self.msg

class PgConnectionError(Exception):
    'PostgreSQL Connection Failed.'
    def __init__(self):
        self.msg = 'PostgreSQL Connection Failed.'
    def __str__(self):
        return self.msg

