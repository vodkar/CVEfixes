[![source under MIT licence](https://img.shields.io/badge/source%20license-MIT-green)](LICENSE.txt)
[![data under CC BY 4.0 license](https://img.shields.io/badge/data%20license-CC%20BY%204.0-green)](https://creativecommons.org/licenses/by/4.0/)

# CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software

_CVEfixes_ is a comprehensive vulnerability dataset that is automatically
collected and curated from Common Vulnerabilities and Exposures
(CVE) records in the public [U.S. National Vulnerability Database (NVD)](https://nvd.nist.gov/).
The goal is to support data-driven security
research based on source code and source code metrics related to fixes
for CVEs in the NVD by providing detailed information at different
interlinked levels of abstraction, such as the commit-, file-, and
method level, as well as the repository- and CVE level.

This repository includes the code to replicate the data collection. 
The complete process has been documented in the paper _"CVEfixes: 
Automated Collection of Vulnerabilities and Their Fixes from Open-
Source Software"_, a copy of which you will find in the Doc folder.

Because of limitations in GitHub storage, the dataset itself is 
released via Zenodo with DOI:
[10.5281/zenodo.4476563](https://doi.org/10.5281/zenodo.4476563).

The latest release, v1.0.8, covers all published CVEs up to 23 July 2024. 
All open-source projects that were reported in CVE records in the 
NVD in this time frame and had publicly available git repositories 
were fetched and considered for the construction of this vulnerability 
dataset. The dataset is organized as a relational database and covers 
12107 vulnerability fixing commits in 4249 open source projects for 
a total of 11873 CVEs in 272 different Common Weakness Enumeration 
(CWE) types. The dataset includes the source code before and after 
changing 51342 files and 138974 functions. The collection took 48 
hours with 4 workers (AMD EPYC Genoa-X 9684X).

  * instructions for using _CVEfixes_ are in the 
    first section of [INSTALL.md](INSTALL.md).
  * requirements for gathering _CVEfixes_ from scratch 
    are in [REQUIREMENTS.md](REQUIREMENTS.md).
  * instructions for gathering _CVEfixes_ from scratch 
    are in the second section of [INSTALL.md](INSTALL.md).


## Citation and Zenodo links

Please site this work by referring to the paper: 
> Guru Bhandari, Amara Naseer, and Leon Moonen. 2021. CVEfixes:
> Automated Collection of Vulnerabilities and Their Fixes from
> Open-Source Software. In Proceedings of the 17th International
> Conference on Predictive Models and Data Analytics in Software
> Engineering (PROMISE '21). ACM, 10 pages.
> <https://doi.org/10.1145/3475960.3475985>

    @inproceedings{bhandari2021:cvefixes,
        title = {{CVEfixes: Automated Collection of Vulnerabilities  and Their Fixes from Open-Source Software}},
        booktitle = {{Proceedings of the 17th International Conference on Predictive Models and Data Analytics in Software Engineering (PROMISE '21)}},
        author = {Bhandari, Guru and Naseer, Amara and Moonen, Leon},
        year = {2021},
        pages = {10},
        publisher = {{ACM}},
        doi = {10.1145/3475960.3475985},
        copyright = {Open Access},
        isbn = {978-1-4503-8680-7},
        language = {en}
    }

The GitHub repository containing the code to automatically collect the
dataset can be found at <https://github.com/secureIT-project/CVEfixes>,
released with DOI:
[10.5281/zenodo.5111494](https://doi.org/10.5281/zenodo.5111494). The 
dataset has been released on Zenodo with DOI:
[10.5281/zenodo.4476563](https://doi.org/10.5281/zenodo.4476563). 


## Collecting the dataset (Parquet/DuckDB backend)

The new collection pipeline replaces the original SQLite backend with
columnar Parquet files and a DuckDB catalog.  Source code snapshots are
stored in a content-addressable blob store (SHA-256 keyed, zstd-19
compressed) so identical files across thousands of CVEs are stored only
once.

### Prerequisites

```
pip install -r requirements.txt   # or: pip install polars pyarrow duckdb zstandard pydriller requests
```

Create a `.CVEfixes.ini` configuration file (see `INSTALL.md` for details
and `example.CVEfixes.ini` for a template):

```ini
[CVEfixes]
database_path = Data          ; raw NVD/CWE JSON cache
parquet_path  = parquet       ; output directory
duckdb_path   = cvefixes.duckdb
num_workers   = 4
logging_level = INFO

[GitHub]
user  = your_github_username
token = ghp_your_personal_access_token
```

A GitHub token is strongly recommended — without one the GitHub API is
rate-limited to ~25 requests per hour, which is not enough for a full
collection.

### Running a full collection

```console
python collect.py
```

The process downloads NVD feeds (2002–present), traverses all referenced
git repositories, and writes Parquet + DuckDB files under `parquet/`.

**Resuming after a failure** — the script writes a checkpoint file
(`parquet/collection_state.json`) after each major step.  If the process
is interrupted for any reason, just re-run the same command and it will
pick up from where it left off:

```console
python collect.py          # interrupted, e.g. by a network error
# ... fix the issue ...
python collect.py          # resumes automatically from last checkpoint
```

To force a completely clean restart (discards checkpoint and staging files):

```console
python collect.py --reset
python collect.py
```

### Other modes

```console
# Quick smoke test: current-year CVEs, 25 commits, ~10-15 minutes
python collect.py --sample

# Incremental weekly update (new CVEs only, rewrites only affected partitions)
python collect.py --update

# Rebuild the DuckDB catalog without re-collecting (e.g. after manual edits)
python collect.py --catalog-only
```

### Output layout

```
parquet/
  collection_state.json     ← checkpoint (deleted on success)
  metadata/
    cve.parquet             ← sorted by published_date
    fixes.parquet
    cwe.parquet
    cwe_classification.parquet
    repository.parquet
    commits.parquet
  file_change/
    language=C/data.parquet
    language=Python/data.parquet
    …                       ← hive-partitioned by programming language
  method_change/
    language=C/data.parquet
    …
  blobs/
    ab/cdef….zst            ← content-addressable source code (SHA-256, zstd-19)
cvefixes.duckdb             ← DuckDB views over all Parquet files
```

### Querying with DuckDB

```python
import duckdb

con = duckdb.connect("cvefixes.duckdb")

# All Python file changes with their CVE IDs
con.sql("""
    SELECT f.cve_id, fc.filename, fc.num_lines_added, fc.num_lines_deleted
    FROM fixes f
    JOIN file_change fc ON f.hash = fc.hash
    WHERE fc.programming_language = 'Python'
    LIMIT 10
""").show()
```

### Estimated resource requirements (full dataset)

| Resource | Estimate |
|----------|----------|
| Disk (raw NVD JSON cache) | ~8 GB |
| Disk (blob store, zstd-19) | ~150–200 GB |
| Disk (Parquet files) | ~2–5 GB |
| RAM | 8 GB minimum, 16 GB recommended |
| CPU | 4+ cores (set `num_workers` accordingly) |
| Time | 24–48 h on a modern machine with a fast connection |

---

## Acknowledgement

This work has been financially supported by the Research Council of
Norway through the secureIT project (RCN contract \#288787).
