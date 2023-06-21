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


# Replace the last occurrence of old with new in s
def rreplace(s, old, new, occurrence):
    li = s.rsplit(old, occurrence)
    return new.join(li)


class SecurityFinding:
    def __init__(self, cwe: string, file_path: string, function_name: string, line_number: int, language: str):
        self.cwe = cwe
        self.file_path = file_path
        self.function_name = function_name
        self.line_number = line_number
        self.language = language

    def vuln_name(self) -> string:
        if self.cwe.lower() == 'cwe-89':
            return 'Sql Injection'

        if self.cwe.lower() == 'cwe-23':
            return 'Path Traversal'

        if self.cwe.lower() == 'cwe-611':
            return 'XXE'

        raise Exception(f'Unsupported CWE {self.cwe}')
