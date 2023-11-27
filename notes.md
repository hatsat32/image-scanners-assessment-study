# Some Notes

Check for empty files:

```
ls -alh trivy/ | grep 'K Nov' -v | grep 'M Nov' -v
ls -alh grype/ | grep 'K Nov' -v | grep 'M Nov' -v
ls -alh snyk/  | grep 'K Nov' -v | grep 'M Nov' -v
```

Check for different files:

```
ls trivy/ -1 > ls.trivy.txt
ls grype/ -1 > ls.grype.txt
ls snyk/ -1 > ls.snyk.txt
md5sum ls.*
```

Check for file count:

```
ls -1 trivy/ | wc
ls -1 grype/ | wc
ls -1 snyk/ | wc
```
