FROM python:3.13-slim
WORKDIR /app
COPY check_fortinet_vuln.py EGBL.config requirements.txt /app/
RUN pip install --no-cache-dir --requirement requirements.txt
ENTRYPOINT ["python", "check_fortinet_vuln.py"]
CMD ["-h"]