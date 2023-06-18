import os
import string

import openai

from utils import read_file, write_file, append_to_file, SecurityFinding


class SecurityBot:
    def __init__(self):
        self.chat_history = [{"role": "system", "content": "You are an application security expert."}]

    def explain_finding(self, finding: SecurityFinding, output_path: string) -> None:
        source_code = read_file(finding.file_path)

        explain_prompt = f'My vulnerability scanner detected {finding.vuln_name()} in the below file. ' \
                         f'The vulnerability is located in function {finding.function_name}, line {finding.line_number}. ' \
                         f'I want you to generate a markdown file that explains this vulnerability. ' \
                         f'Split the output into four sections and title each section. ' \
                         f'The first section must be titled "What is {finding.vuln_name()}?" and must only contain ' \
                         f'a brief description of the vulnerability. ' \
                         f'The second section must be titled "Why is your code vulnerable to {finding.vuln_name()}?" ' \
                         f'and must explain why the supplied code is vulnerable. ' \
                         f'This section must show the part of the code that is vulnerable. ' \
                         f'Include that part as the code snippet. ' \
                         f'This section must not show how the vulnerability can be exploited. ' \
                         f'This section must not show how the vulnerability can be fixed. ' \
                         f'The third section must be titled "How can {finding.vuln_name()} be exploited?" ' \
                         f'and must show an example of how this vulnerability can be exploited in the input code. ' \
                         f'The fourth section must be titled "How can {finding.vuln_name()} be fixed?" ' \
                         f'and must show and explain the fixed code. ' \
                         f'This is the vulnerable code: {os.linesep}{source_code}'

        gpt_response = self._query_openai(explain_prompt)
        write_file(output_path, gpt_response)

    def ask_question(self, finding: SecurityFinding, user_input: string, output_path: string) -> None:
        chat_prompt = f'I have a further question regarding the {finding.vuln_name()} in the that file. ' \
                         f'Output your answer as markdown. {user_input}'

        gpt_response = self._query_openai(chat_prompt)
        append_to_file(output_path, f'{os.linesep} ## {user_input} {os.linesep}')
        append_to_file(output_path, gpt_response)

    def _query_openai(self, user_prompt: string) -> string:
        openai_api_key = os.getenv("OPENAI_API_KEY", None)
        if openai_api_key is None:
            raise Exception("OPENAI_API_KEY env variable not set, cannot run GPT as a SAST tool")

        self.chat_history.append({"role": "user", "content": user_prompt})

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=self.chat_history,
            temperature=0.1,
        )

        response_content = response.get('choices', [{}])[0].get('message', {}).get('content', None)
        if response_content is None:
            raise Exception(f'Invalid GPT response: + {response}')

        self.chat_history.append({"role": "assistant", "content": response_content})

        return response_content
