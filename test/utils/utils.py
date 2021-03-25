def read_file_bytes(filename):
    with open(filename, 'rb') as file:
        return file.read()
