# Arc CLI dumps

Dump of Arc CLI code to better understand how it works

1. All versions: https://azcliextensionsync.blob.core.windows.net/index1/index.json
2. Check for updates
```powershell
az extension list-versions -n connectedk8s
az extension list-versions -n arcdata
az extension list-versions -n k8s-extension
```
2. Download wheel from:
```text
https://azcliprod.blob.core.windows.net/cli-extensions/connectedk8s-1.X.X-py2.py3-none-any.whl
https://azurearcdatacli.blob.core.windows.net/cli-extensions/arcdata-1.X.X-py2.py3-none-any.whl
https://azcliprod.blob.core.windows.net/cli-extensions/k8s_extension-1.X.X-py3-none-any.whl
https://arcplatformcliextprod.blob.core.windows.net/customlocation/customlocation-0.1.3-py2.py3-none-any.whl
```
3 Unpacked `whl` file via 7-zip

# Versions
## connectedk8s - `1.2.8`
## arcdata - `1.4.0`
## k8s-extension `1.2.2`
## customlocation `0.1.3`