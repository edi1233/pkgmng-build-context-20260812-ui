FROM harbor.edi-it.com/airuneers/pkgmng:20260813-sources-c9f4888

COPY app/main.py /app/app/main.py
COPY app/inventory_controls.py /app/app/inventory_controls.py

ENV APP_VERSION=20260813-expandtext-main

CMD ["python", "-m", "app.inventory_controls"]
