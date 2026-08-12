FROM harbor.edi-it.com/airuneers/pkgmng:20260812-security-644a461

USER root
COPY app/remediation_patch.py /app/app/remediation_patch.py
RUN chown 10001:0 /app/app/remediation_patch.py

USER pkgmng
EXPOSE 8080

CMD ["python", "-m", "app.remediation_patch"]
