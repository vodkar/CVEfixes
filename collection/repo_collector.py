"""
Repository metadata collector — fetches GitHub/GitLab metadata and validates
repo availability.

Replaces the relevant parts of Code/collect_projects.py.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import polars as pl
import requests

logger = logging.getLogger("cvefixes.repo_collector")


def find_unavailable_urls(urls: list[str]) -> list[str]:
    """Return URLs that respond with HTTP 4xx or redirect to a login page."""
    unavailable: list[str] = []
    sleep_time = 0
    for url in urls:
        try:
            resp = requests.head(url, timeout=10, allow_redirects=False)
            while resp.status_code == 429:
                sleep_time += 10
                time.sleep(sleep_time)
                resp = requests.head(url, timeout=10, allow_redirects=False)
            sleep_time = 0

            is_gitlab_redirect = (
                resp.is_redirect
                and resp.headers.get("location") == "https://gitlab.com/users/sign_in"
            )
            if resp.status_code >= 400 or is_gitlab_redirect:
                logger.debug("Unavailable (%d): %s", resp.status_code, url)
                unavailable.append(url)
        except requests.RequestException as exc:
            logger.warning("Request error for %s: %s", url, exc)
            unavailable.append(url)
    return unavailable


def get_github_meta(repo_url: str, user: str | None, token: str | None) -> dict | None:
    """
    Fetch metadata for a GitHub repository via the API.

    Returns a dict with repo metadata, or None on failure.
    """
    try:
        from github import Github
        from github.GithubException import BadCredentialsException, UnknownObjectException

        owner = repo_url.rstrip("/").split("/")[-2]
        project = repo_url.rstrip("/").split("/")[-1]

        if token and token != "None":
            g = Github(login_or_token=token)
        elif user and user != "None":
            g = Github()
        else:
            g = Github()

        try:
            repo = g.get_repo(f"{owner}/{project}")
            return {
                "repo_url": repo_url,
                "repo_name": repo.full_name,
                "description": repo.description,
                "date_created": repo.created_at.date().isoformat() if repo.created_at else None,
                "date_last_push": repo.pushed_at.date().isoformat() if repo.pushed_at else None,
                "homepage": repo.homepage,
                "repo_language": repo.language,
                "owner": owner,
                "forks_count": repo.forks,
                "stars_count": repo.stargazers_count,
            }
        except BadCredentialsException as exc:
            logger.warning("Bad credentials for %s: %s", repo_url, exc)
        except UnknownObjectException:
            logger.warning("Repo not found: %s", repo_url)
        except Exception as exc:
            logger.warning("GitHub API error for %s: %s", repo_url, exc)
    except ImportError:
        logger.warning("PyGithub not installed — skipping GitHub metadata")
    return None


def collect_repo_metadata(
    df_fixes: pl.DataFrame,
    staging_path: str | Path,
    github_user: str | None = None,
    github_token: str | None = None,
) -> pl.DataFrame:
    """
    For each unique repo_url in *df_fixes*, attempt to fetch GitHub metadata
    and write a repository staging Parquet.

    Returns the repository DataFrame.
    """
    staging_path = Path(staging_path)
    staging_path.mkdir(parents=True, exist_ok=True)

    repo_urls = df_fixes["repo_url"].unique().to_list()
    rows: list[dict] = []

    for idx, url in enumerate(repo_urls, 1):
        logger.info("Fetching metadata %d/%d: %s", idx, len(repo_urls), url)
        if "github." in url:
            meta = get_github_meta(url, github_user, github_token)
        else:
            meta = None

        if meta is None:
            # Placeholder row for repos we couldn't fetch metadata for
            owner = url.rstrip("/").split("/")[-2] if "/" in url else "unknown"
            meta = {
                "repo_url": url,
                "repo_name": None,
                "description": None,
                "date_created": None,
                "date_last_push": None,
                "homepage": None,
                "repo_language": None,
                "owner": owner,
                "forks_count": None,
                "stars_count": None,
            }
        rows.append(meta)

    df_repo = pl.DataFrame(rows) if rows else pl.DataFrame()

    out = staging_path / "repository_staging.parquet"
    df_repo.write_parquet(out, compression="zstd")
    logger.info("Wrote %d repository records to %s", len(df_repo), out)
    return df_repo
