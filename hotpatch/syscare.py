import subprocess
from typing import List

SUCCEED = 0
FAIL = 255


def cmd_output(cmd):
    try:
        result = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result.wait()
        return result.stdout.read().decode('utf-8'), result.returncode
    except Exception as e:
        print("error: ", e)
        return str(e), FAIL


class Syscare:
    @classmethod
    def list(cls, condition=None) -> List[dict]:
        """
        Target                                Name                       Status
        redis-6.2.5-1.oe2203                  CVE-2021-23675             ACTIVED
        kernel-5.10.0-60.80.0.104.oe2203      modify-proc-version        ACTIVED
        """
        cmd = ["syscare", "list"]
        list_output, return_code = cmd_output(cmd)
        if return_code != SUCCEED:
            return []

        content = list_output.split('\n')
        if len(content) <= 2:
            return []

        header = content[0].split()
        result = []
        for item in content[1:-1]:
            tmp = dict(zip(header, item.split()))
            if not condition or cls.judge(tmp, condition):
                result.append(tmp)
        return result

    @staticmethod
    def judge(content: dict, condition: dict):
        for key, value in condition.items():
            if content.get(key) != value:
                return False
        return True

    @staticmethod
    def status(patch_name: str):
        cmd = ["syscare", "status", patch_name]
        output, return_code = cmd_output(cmd)

        return output, return_code

    @staticmethod
    def active(patch_name: str):
        cmd = ["syscare", "active", patch_name]
        output, return_code = cmd_output(cmd)

        return output, return_code

    @staticmethod
    def deactive(patch_name: str):
        cmd = ["syscare", "deactive", patch_name]
        output, return_code = cmd_output(cmd)

        return output, return_code

    @staticmethod
    def remove(patch_name: str):
        cmd = ["syscare", "remove", patch_name]
        output, return_code = cmd_output(cmd)

        return output, return_code

    @staticmethod
    def apply(patch_name: str):
        cmd = ["syscare", "apply", patch_name]
        output, return_code = cmd_output(cmd)

        return output, return_code

    @staticmethod
    def save():
        cmd = ["syscare", "save"]
        output, return_code = cmd_output(cmd)

        return output, return_code

    @staticmethod
    def restore():
        cmd = ["syscare", "restore"]
        output, return_code = cmd_output(cmd)

        return output, return_code

    @staticmethod
    def accept(patch_name: str):
        cmd = ["syscare", "accept", patch_name]
        output, return_code = cmd_output(cmd)

        return output, return_code
