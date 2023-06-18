import os
import string


def read_file(file_path: string) -> string:
    with open(file_path, mode='r', encoding='utf-8') as file:
        file_content = file.read()
        return file_content


def write_file(file_path: string, file_content: string) -> None:
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(file_content)


def append_to_file(file_path: string, file_content: string) -> None:
    with open(file_path, 'a', encoding='utf-8') as file:
        file.write(file_content)
        file.write(os.linesep)


class SecurityFinding:
    def __init__(self, cwe: string, file_path: string, function_name: string, line_number: int):
        self.cwe = cwe
        self.file_path = file_path
        self.function_name = function_name
        self.line_number = line_number

    def vuln_name(self) -> string:
        if self.cwe.lower() == 'cwe-89':
            return 'Sql Injection'

        raise Exception(f'Unsupported CWE {self.cwe}')
