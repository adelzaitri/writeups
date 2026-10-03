FROM python:3.12-slim
# docling-slim WITHOUT the [standard] extra. The metapackage `docling` pulls
# docling-slim[standard], which drags in torch (a 554MB wheel plus its CUDA stack) —
# none of which the ImageResourceLoader path touches. [format-html] adds only the HTML
# backend's own parser deps.
RUN pip install --no-cache-dir "docling-slim[format-html]==2.130.0"
