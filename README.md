For setting up CodeQL database to be queried:
```bash
codeql database create python-db --language=python --source-root=test-code --overwrite
```
For running query on previously built database:
```bash
codeql query run --database=python-db custom-queries/python/gdpr/queries/SensitiveData.ql
```
