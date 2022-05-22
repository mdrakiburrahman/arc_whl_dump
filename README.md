# Arc CLI dumps

Dump of Arc CLI code to better understand how it works

1. All versions: https://azcliextensionsync.blob.core.windows.net/index1/index.json
2. Check for updates
```powershell
az extension list-versions -n connectedk8s
az extension list-versions -n arcdata
```
2. Download wheel from:
```text
https://azcliprod.blob.core.windows.net/cli-extensions/connectedk8s-1.2.8-py2.py3-none-any.whl
https://azurearcdatacli.blob.core.windows.net/cli-extensions/arcdata-1.X.X-py2.py3-none-any.whl
```
3 Unpacked `whl` file via 7-zip

# Versions
## connectedk8s - `1.2.8`
## arcdata - `1.4.0`
