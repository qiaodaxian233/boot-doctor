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

# 实测 annotation 正文超过约 4KB 会被截断；每步最多 10 条。取输出末尾（失败详情在最后）
CHUNK_BYTES, MAX_CHUNKS = 3800, 9
data = text.encode("utf-8")[-CHUNK_BYTES * MAX_CHUNKS:]
chunks = [data[i:i + CHUNK_BYTES].decode("utf-8", "ignore")
          for i in range(0, len(data), CHUNK_BYTES)] or ["（无输出）"]


def esc(s):
    return s.replace("%", "%25").replace("\r", "").replace("\n", "%0A")


for i, c in enumerate(chunks, 1):
    level = "notice" if p.returncode == 0 else "error"
    print("::%s title=%s rc=%d (%d/%d)::%s" % (level, title, p.returncode, i, len(chunks), esc(c)))
sys.exit(p.returncode)
