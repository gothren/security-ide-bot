import os
import string

import openai

from utils import read_file, rreplace, SecurityFinding


class SecurityBot:
    def __init__(self, finding: SecurityFinding):
        self.finding = finding

        source_code = read_file(self.finding.file_path)
        system_content = f'You are an application security expert. ' \
                         f'A vulnerability scanner detected {self.finding.vuln_name()} in the below file. ' \
                         f'The vulnerability is located in ' \
                         f'function {self.finding.function_name}, line {self.finding.line_number}. ' \
                         f'Your job will be to explain the vulnerability and provide fix suggestions. ' \
                         f'You must output all code snippets and fix suggestions in ' \
                         f'{self.finding.language} programming language. ' \
                         f'This is the content of the vulnerable file: {os.linesep}{source_code}. '

        self.chat_history = [{"role": "system", "content": system_content}]

    def explain_finding(self) -> string:
        explain_prompt = f'I want you to generate a markdown file that explains the vulnerability. ' \
                         f'You must title the file "{self.finding.vuln_name()} in {self.finding.function_name}". ' \
                         f'Split the output into four sections and title each section. ' \
                         f'The first section must be titled ' \
                         f'"What is {self.finding.vuln_name()}?" and must only contain ' \
                         f'a brief description of the vulnerability. ' \
                         f'The second section must be titled ' \
                         f'"Why is your code vulnerable to {self.finding.vuln_name()}?" ' \
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

        return self._query_openai(explain_prompt)

    def ask_question(self, user_input: string) -> string:
        chat_prompt = f'I have a further question regarding the {self.finding.vuln_name()} in the that file. ' \
                         f'Output your answer as markdown. {user_input}'

        return self._query_openai(chat_prompt)

    def generate_fix(self):
        fix_prompt = f'Can you regenerate the entire file with the latest fix that you proposed? ' \
                     f'Use the latest fix that you suggested. Do not use your previous fix suggestions. ' \
                     f'You must output only the fixed code. ' \
                     f'Do not output any text that is not code. ' \
                     f'Do not explain what you did. Do not output any markdown. ' \
                     f'Ignore the previous request to output markdown. ' \

        fix_content = self._query_openai(fix_prompt)

        # Despite prompt engineering, the model will sometimes output as markdown.
        # This is a bit nasty workaround
        if fix_content.startswith('```' + self.finding.language):
            fix_content = fix_content.replace('```' + self.finding.language, '', 1)
        if fix_content.startswith('```'):
            fix_content = fix_content.replace('```', '', 1)
        if fix_content.endswith('```'):
            fix_content = rreplace(fix_content, '```', '', 1)

        return fix_content

    def _query_openai(self, user_prompt: string) -> string:
        openai_api_key = os.getenv("OPENAI_API_KEY", None)
        if openai_api_key is None:
            raise Exception("OPENAI_API_KEY env variable not set, cannot run GPT as a SAST tool")

        self.chat_history.append({"role": "user", "content": user_prompt})

        response = openai.ChatCompletion.create(
            # model="gpt-4",
            model="gpt-3.5-turbo",
            messages=self.chat_history,
            temperature=0.1,
        )

        response_content = response.get('choices', [{}])[0].get('message', {}).get('content', None)
        if response_content is None:
            raise Exception(f'Invalid GPT response: + {response}')

        self.chat_history.append({"role": "assistant", "content": response_content})

        return response_content
