import argparse
import os
import string
import sys
import colorama
import termcolor
import pyfiglet

from bot import SecurityBot
from utils import SecurityFinding, write_file, append_to_file


def main():
    colorama.init()

    parser = argparse.ArgumentParser(
        prog='security-ide-bot',
        description='An interactive bot that helps you deal with a Snyk finding')

    parser.add_argument('--cwe', help='The CWE of the issue found', required=True)
    parser.add_argument('--file-path', help='The path to the vulnerable file', required=True)
    parser.add_argument(
        '--file-location',
        help='The location of vuln in the file, in the form function_name:line_number',
        required=True)
    parser.add_argument('--language', help='The programming language of the vulnerable code', required=True)
    parser.add_argument(
        '--output-path',
        help='The path to the output markdown file, defaults to "markdown.md" in the current working dir',
        default='markdown.md')

    args = parser.parse_args()
    cwe = args.cwe
    file_path = args.file_path
    file_location = args.file_location

    func_and_line = file_location.split(':')
    if len(func_and_line) != 2:
        raise Exception('Invalid file_location input. Has to be of the form function_name:line_number')

    finding = SecurityFinding(cwe, file_path, func_and_line[0], int(func_and_line[1]), args.language)

    sec_bot = SecurityBot(finding)

    interactive_shell(finding, args.output_path, sec_bot)


def process_shell_input(
        user_input: string,
        finding: SecurityFinding,
        output_path: string,
        sec_bot: SecurityBot) -> None:

    user_input = user_input.strip()
    if user_input == "help":
        print_help()
    elif user_input == "exit":
        sys.exit()
    elif user_input == "fix":
        fix_content = sec_bot.generate_fix()
        write_file(finding.file_path, fix_content)
        print('Fix applied!')

    elif user_input == "explain":
        explanation = sec_bot.explain_finding()
        write_file(output_path, explanation)
    else:
        chat_output = sec_bot.ask_question(user_input)
        append_to_file(output_path, f'{os.linesep} ## {user_input} {os.linesep}')
        append_to_file(output_path, chat_output)


def interactive_shell(finding: SecurityFinding, output_path: string, sec_bot: SecurityBot) -> None:
    termcolor.cprint(pyfiglet.figlet_format('Sec IDE Bot!', font='starwars'))
    print_snyk_finding(finding)
    print_help()
    while True:
        user_input = input("> ")
        process_shell_input(user_input, finding, output_path, sec_bot)


def print_help() -> None:
    print(colorama.Fore.GREEN + 'Available commands are:')
    print(colorama.Style.BRIGHT + '  explain:' + colorama.Style.NORMAL + ' explains the vulnerability')
    print(colorama.Style.BRIGHT + '  fix:' + colorama.Style.NORMAL + ' fixes the vulnerability')
    print(colorama.Style.BRIGHT + '  help:' + colorama.Style.NORMAL + ' print this message again')
    print(colorama.Style.BRIGHT + '  exit:' + colorama.Style.NORMAL + ' terminates the interactive shell')
    print('Or just type anything else in the shell and the bot will help you out')


def print_snyk_finding(finding: SecurityFinding):
    print(colorama.Fore.GREEN + f'Running the bot for the following finding: ')
    print(colorama.Fore.GREEN + f'  CWE: {finding.cwe}')
    print(colorama.Fore.GREEN + f'  Vuln name: {finding.vuln_name()}')
    print(colorama.Fore.GREEN + f'  File: {finding.file_path}')
    print(colorama.Fore.GREEN + f'  Function: {finding.function_name}:{finding.line_number}')
    print(colorama.Fore.GREEN + f'  Language: {finding.language}')

    print()



if __name__ == '__main__':
    main()
