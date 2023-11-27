import json, os, csv

def get_imgname_from_filename(filename):
    if "__" in filename:
        _imgname = filename.removesuffix(".json").split("__")
        if len(_imgname) == 2:
            imgname = f"{_imgname[0]}:{_imgname[1]}"
        else:
            imgname = f"{_imgname[0]}/{_imgname[1]}:{_imgname[2]}"
    else:
        imgname = filename.removesuffix(".json")
    return imgname

def trivy_agg(csvwriter, _dir):
    files = os.listdir(f"./{_dir}/trivy/")

    for file in files:
        with open(f"./{_dir}/trivy/{file}") as f:
            json_content = json.loads(f.read())

        if "Results" not in json_content:
            continue

        imgname = get_imgname_from_filename(file)

        for result in json_content["Results"]:
            if "Vulnerabilities" not in result:
                continue

            for vuln in result["Vulnerabilities"]:
                csvwriter.writerow({
                    "scanner": "trivy",
                    "imagetype": _dir,
                    "image": imgname,
                    "id": vuln["VulnerabilityID"],
                    "pkgname": vuln["PkgName"],
                    "pkgversion": vuln["InstalledVersion"],
                    # "status": vuln["Status"],
                    "severity": vuln["Severity"].lower(),
                })


def grype_agg(csvwriter, dirname):
    files = os.listdir(f"./{dirname}/grype/")

    for file in files:
        with open(f"./{dirname}/grype/{file}") as f:
            json_content = json.loads(f.read())

        if "matches" not in json_content:
            continue

        imgname = get_imgname_from_filename(file)

        for vuln in json_content["matches"]:
            # print(vuln["matchDetails"][0]["searchedBy"])

            _package=None
            try:
                _package = vuln["matchDetails"][0]["searchedBy"]["package"]
            except:
                _package = vuln["matchDetails"][0]["searchedBy"]["Package"]

            csvwriter.writerow({
                "scanner": "grype",
                "imagetype": dirname,
                "image": imgname,
                "id": vuln["vulnerability"]["id"],
                "pkgname": _package["name"],
                "pkgversion": _package["version"],
                "severity": vuln["vulnerability"]["severity"].lower(),
            })

def snyk_agg(csvwriter, dirname):
    files = os.listdir(f"./{dirname}/snyk/")

    for file in files:
        with open(f"./{dirname}/snyk/{file}") as f:
            json_content = json.loads(f.read())

        if "vulnerabilities" not in json_content:
            continue
        
        imgname = get_imgname_from_filename(file)

        for vuln in json_content["vulnerabilities"]:
            _id = vuln["id"]

            try:
                _id = vuln["identifiers"]["CVE"][0]
            except:
                pass

            csvwriter.writerow({
                "scanner": "snyk",
                "imagetype": dirname,
                "image": imgname,
                "id": _id,
                "pkgname": vuln["packageName"],
                "pkgversion": vuln["version"],
                "severity": vuln["severity"].lower(),
            })



def main():
    dirs = ["library", "opensource", "verified"]
    with open ("totalscan.csv", "w") as csvfile:
        csvwriter = csv.DictWriter(
            csvfile,
            fieldnames=["scanner", "imagetype", "image", 'id', 'pkgname', "pkgversion", "severity"]
        )
        csvwriter.writeheader()

        for dirname in dirs:
            trivy_agg(csvwriter, dirname)
            grype_agg(csvwriter, dirname)
            snyk_agg(csvwriter, dirname)

if __name__ == "__main__":
    main()
