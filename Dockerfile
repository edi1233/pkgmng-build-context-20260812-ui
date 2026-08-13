FROM harbor.edi-it.com/airuneers/pkgmng:20260813-sources-c9f4888

COPY app/inventory_controls.py /app/app/inventory_controls.py

ENV APP_VERSION=20260813-controls-abb8de4

CMD ["python", "-m", "app.inventory_controls"]
