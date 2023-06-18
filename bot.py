import os
import string

import openai

from utils import read_file, SecurityFinding


class SecurityBot:
    def __init__(self):
        self.chat_history = [{"role": "system", "content": "You are an application security expert."}]

    def explain_finding(self, finding: SecurityFinding) -> string:
        source_code = read_file(finding.file_path)

        explain_prompt = f'My vulnerability scanner detected {finding.vuln_name()} in the below file. ' \
                         f'The vulnerability is located in ' \
                         f'function {finding.function_name}, line {finding.line_number}. ' \
                         f'I want you to generate a markdown file that explains this vulnerability. ' \
                         f'Split the output into four sections and title each section. ' \
                         f'The first section must be titled "What is {finding.vuln_name()}?" and must only contain ' \
                         f'a brief description of the vulnerability. ' \
                         f'The second section must be titled "Why is your code vulnerable to {finding.vuln_name()}?" ' \
                         f'and must explain why the supplied code is vulnerable. ' \
                         f'This section must show the section of the code that is vulnerable. ' \
                         f'You must include in the output the vulnerable code as the code snippet. ' \
                         f'This section must not show how the vulnerability can be exploited. ' \
                         f'This section must not show how the vulnerability can be fixed. ' \
                         f'The third section must be titled "How can your code be exploited?" ' \
                         f'and must show an example of how this vulnerability can be exploited in the input code. ' \
                         f'Provide a step by step explanation of the exploit. ' \
                         f'The fourth section must be titled "How can your code be fixed?" ' \
                         f'and must show and explain the fixed code. ' \
                         f'You must show only part of the code that is getting fixed, ' \
                         f'do not show the entire function. ' \
                         f'This is the vulnerable code: {os.linesep}{source_code}'

        return self._query_openai(explain_prompt)

    def ask_question(self, finding: SecurityFinding, user_input: string) -> string:
        chat_prompt = f'I have a further question regarding the {finding.vuln_name()} in the that file. ' \
                         f'Output your answer as markdown. {user_input}'

        return self._query_openai(chat_prompt)

    def generate_fix(self):
        fix_prompt = f'Can you regenerate the entire file with the latest fix that you proposed? ' \
                     f'You must output only the fixed file content. Do not output any other text. ' \
                     f'Output the fixed file as plain text not as markdown. '

        return self._query_openai(fix_prompt)

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
