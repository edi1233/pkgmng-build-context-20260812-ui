FROM harbor.edi-it.com/airuneers/pkgmng:20260812-security-644a461

USER root
COPY app/remediation_patch.py /app/app/remediation_patch.py
COPY app/route_fix.py /app/app/route_fix.py
RUN chown 10001:0 /app/app/remediation_patch.py /app/app/route_fix.py

USER pkgmng
EXPOSE 8080

CMD ["python", "-m", "app.route_fix"]
