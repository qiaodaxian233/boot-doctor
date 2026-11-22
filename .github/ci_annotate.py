# -*- coding: utf-8 -*-
"""CI 辅助：跑一条命令，原样输出，同时把输出尾部写成 annotation。

原始日志要从 Azure Blob 下载，有些环境（比如受限的协作沙箱）访问不了；
annotation 走 GitHub API，在 PR 的 Checks 页和 API 里都能直接看到。
用法：python .github/ci_annotate.py <标题> <命令...>
"""
import subprocess
import sys

title, cmd = sys.argv[1], sys.argv[2:]
p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
text = p.stdout.decode("utf-8", "replace")
sys.stdout.write(text)
sys.stdout.flush()

CHUNK, MAX_CHUNKS = 30000, 8                  # GitHub 每步最多 10 条 notice、单条 64KB
tail = text[-CHUNK * MAX_CHUNKS:]
chunks = [tail[i:i + CHUNK] for i in range(0, len(tail), CHUNK)] or ["（无输出）"]


def esc(s):
    return s.replace("%", "%25").replace("\r", "").replace("\n", "%0A")


for i, c in enumerate(chunks, 1):
    level = "notice" if p.returncode == 0 else "error"
    print("::%s title=%s rc=%d (%d/%d)::%s" % (level, title, p.returncode, i, len(chunks), esc(c)))
sys.exit(p.returncode)
