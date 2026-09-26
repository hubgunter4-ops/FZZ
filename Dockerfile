FROM python:3.11-slim

WORKDIR /opt/fzz
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt
COPY fzztool ./fzztool
COPY fzz ./fzz
COPY README.md ./README.md
RUN chmod +x ./fzz && pip install --no-cache-dir --no-deps --editable .

ENTRYPOINT ["fzz"]
CMD ["--help"]
